//! Bob's side of SecureJoin handling.

use anyhow::{Context as _, Result};

use super::qrinvite::QrInvite;
use super::HandshakeMessage;
use crate::chat::{is_contact_in_chat, ChatId, ProtectionStatus};
use crate::constants::{self, Blocked, Chattype};
use crate::contact::{Contact, Origin};
use crate::context::Context;
use crate::events::EventType;
use crate::mimeparser::{MimeMessage, SystemMessage};
use crate::securejoin::{encrypted_and_signed, verify_sender_by_fingerprint, ContactId};
use crate::sync::Sync::*;
use crate::tools::{create_smeared_timestamp, time};
use crate::{chat, stock_str};

/// Starts the securejoin protocol with the QR `invite`.
///
/// This will try to start the securejoin protocol for the given QR `invite`.  If it
/// succeeded the protocol state will be tracked in `self`.
///
/// This function takes care of handling multiple concurrent joins and handling errors while
/// starting the protocol.
///
/// # Returns
///
/// The [`ChatId`] of the created chat is returned, for a SetupContact QR this is the 1:1
/// chat with Alice, for a SecureJoin QR this is the group chat.
pub(super) async fn start_protocol(context: &Context, invite: QrInvite) -> Result<ChatId> {
    // A 1:1 chat is needed to send messages to Alice.  When joining a group this chat is
    // hidden, if a user starts sending messages in it it will be unhidden in
    // receive_imf.
    let hidden = match invite {
        QrInvite::Contact { .. } => Blocked::Not,
        QrInvite::Group { .. } => Blocked::Yes,
    };
    let chat_id = ChatId::create_for_contact_with_blocked(context, invite.contact_id(), hidden)
        .await
        .with_context(|| format!("can't create chat for contact {}", invite.contact_id()))?;

    ContactId::scaleup_origin(context, &[invite.contact_id()], Origin::SecurejoinJoined).await?;
    context.emit_event(EventType::ContactsChanged(None));

    // Now start the protocol and initialise the state.
    crate::securejoin::bobstate::start_protocol(context, invite.clone(), chat_id).await?;
    match invite {
        QrInvite::Group { .. } => {
            // For a secure-join we need to create the group and add the contact.  The group will
            // only become usable once the protocol is finished.
            let group_chat_id = joining_chat_id(context, &invite, chat_id).await?;
            if !is_contact_in_chat(context, group_chat_id, invite.contact_id()).await? {
                chat::add_to_chat_contacts_table(
                    context,
                    time(),
                    group_chat_id,
                    &[invite.contact_id()],
                )
                .await?;
            }
            let msg = stock_str::secure_join_started(context, invite.contact_id()).await;
            chat::add_info_msg(context, group_chat_id, &msg, time()).await?;
            Ok(group_chat_id)
        }
        QrInvite::Contact { .. } => {
            // For setup-contact the BobState already ensured the 1:1 chat exists because it
            // uses it to send the handshake messages.
            // Calculate the sort timestamp before checking the chat protection status so that if we
            // race with its change, we don't add our message below the protection message.
            let sort_to_bottom = true;
            let (received, incoming) = (false, false);
            let ts_sort = chat_id
                .calc_sort_timestamp(context, 0, sort_to_bottom, received, incoming)
                .await?;
            if chat_id.is_protected(context).await? == ProtectionStatus::Unprotected {
                let ts_start = time();
                chat::add_info_msg_with_cmd(
                    context,
                    chat_id,
                    &stock_str::securejoin_wait(context).await,
                    SystemMessage::SecurejoinWait,
                    ts_sort,
                    Some(ts_start),
                    None,
                    None,
                )
                .await?;
                chat_id.spawn_securejoin_wait(context, constants::SECUREJOIN_WAIT_TIMEOUT);
            }
            Ok(chat_id)
        }
    }
}

/// Handles `vc-auth-required` and `vg-auth-required` handshake messages.
///
/// # Bob - the joiner's side
/// ## Step 4 in the "Setup Contact protocol"
pub(super) async fn handle_auth_required(
    context: &Context,
    message: &MimeMessage,
) -> Result<HandshakeMessage> {
    // Load all Bob states that expect `vc-auth-required` or `vg-auth-required`.
    let bob_states: Vec<(i64, QrInvite, ChatId)> = context
        .sql
        .query_map(
            "SELECT id, invite, chat_id FROM bobstate",
            (),
            |row| {
                let row_id: i64 = row.get(0)?;
                let invite: QrInvite = row.get(1)?;
                let chat_id: ChatId = row.get(2)?;
                Ok((row_id, invite, chat_id))
            },
            |rows| rows.collect::<Result<Vec<_>, _>>().map_err(Into::into),
        )
        .await?;

    info!(
        context,
        "Bob Step 4 - handling {{vc,vg}}-auth-required message."
    );

    let mut auth_sent = false;
    for (bobstate_row_id, invite, chat_id) in bob_states {
        if !encrypted_and_signed(context, message, invite.fingerprint()) {
            continue;
        }

        if !verify_sender_by_fingerprint(context, invite.fingerprint(), invite.contact_id()).await?
        {
            continue;
        }

        info!(context, "Fingerprint verified.",);
        context
            .sql
            .execute("DELETE FROM bobstate WHERE id=?", (bobstate_row_id,))
            .await?;
        crate::securejoin::bobstate::send_handshake_message(
            context,
            &invite,
            chat_id,
            crate::securejoin::bobstate::BobHandshakeMsg::RequestWithAuth,
        )
        .await?;

        match invite {
            QrInvite::Contact { .. } => {}
            QrInvite::Group { .. } => {
                // The message reads "Alice replied, waiting to be added to the group…",
                // so only show it on secure-join and not on setup-contact.
                let contact_id = invite.contact_id();
                let msg = stock_str::secure_join_replies(context, contact_id).await;
                let chat_id = joining_chat_id(context, &invite, chat_id).await?;
                chat::add_info_msg(context, chat_id, &msg, time()).await?;
            }
        }

        set_peer_verified(
            context,
            invite.contact_id(),
            chat_id,
            message.timestamp_sent,
        )
        .await?;

        context.emit_event(EventType::SecurejoinJoinerProgress {
            contact_id: invite.contact_id(),
            progress: JoinerProgress::RequestWithAuthSent.into(),
        });

        auth_sent = true;
    }

    if auth_sent {
        // Delete the message from IMAP server.
        Ok(HandshakeMessage::Done)
    } else {
        // We have not found any corresponding AUTH codes,
        // maybe another Bob device has scanned the QR code.
        // Leave the message on IMAP server and let the other device
        // process it.
        Ok(HandshakeMessage::Ignore)
    }
}

/// Returns the [`ChatId`] of the chat being joined.
///
/// This is the chat in which you want to notify the user as well.
///
/// When joining a group this is the [`ChatId`] of the group chat, when verifying a
/// contact this is the [`ChatId`] of the 1:1 chat.
/// The group chat will be created if it does not yet exist.
async fn joining_chat_id(
    context: &Context,
    invite: &QrInvite,
    alice_chat_id: ChatId,
) -> Result<ChatId> {
    match invite {
        QrInvite::Contact { .. } => Ok(alice_chat_id),
        QrInvite::Group {
            ref grpid,
            ref name,
            ..
        } => {
            let group_chat_id = match chat::get_chat_id_by_grpid(context, grpid).await? {
                Some((chat_id, _protected, _blocked)) => {
                    chat_id.unblock_ex(context, Nosync).await?;
                    chat_id
                }
                None => {
                    ChatId::create_multiuser_record(
                        context,
                        Chattype::Group,
                        grpid,
                        name,
                        Blocked::Not,
                        ProtectionStatus::Unprotected, // protection is added later as needed
                        None,
                        create_smeared_timestamp(context),
                    )
                    .await?
                }
            };
            Ok(group_chat_id)
        }
    }
}

/// Turns 1:1 chat with SecureJoin peer into protected chat.
pub(crate) async fn set_peer_verified(
    context: &Context,
    contact_id: ContactId,
    chat_id: ChatId,
    timestamp: i64,
) -> Result<()> {
    let contact = Contact::get_by_id(context, contact_id).await?;
    chat_id
        .set_protection(
            context,
            ProtectionStatus::Protected,
            timestamp,
            Some(contact.id),
        )
        .await?;
    Ok(())
}

/// Progress updates for [`EventType::SecurejoinJoinerProgress`].
///
/// This has an `From<JoinerProgress> for usize` impl yielding numbers between 0 and a 1000
/// which can be shown as a progress bar.
pub(crate) enum JoinerProgress {
    /// vg-vc-request-with-auth sent.
    ///
    /// Typically shows as "alice@addr verified, introducing myself."
    RequestWithAuthSent,
    /// Completed securejoin.
    Succeeded,
}

impl From<JoinerProgress> for usize {
    fn from(progress: JoinerProgress) -> Self {
        match progress {
            JoinerProgress::RequestWithAuthSent => 400,
            JoinerProgress::Succeeded => 1000,
        }
    }
}
