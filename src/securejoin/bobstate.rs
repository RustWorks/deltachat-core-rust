//! Secure-Join protocol state machine for Bob, the joiner-side.
//!
//! This module contains the state machine to run the Secure-Join handshake for Bob and does
//! not do any user interaction required by the protocol.  Instead the state machine
//! provides all the information to its driver so it can perform the correct interactions.

use anyhow::Result;

use super::qrinvite::QrInvite;
use super::verify_sender_by_fingerprint;
use crate::chat::{self, ChatId};
use crate::context::Context;
use crate::events::EventType;
use crate::key::{load_self_public_key, DcKey};
use crate::message::{Message, Viewtype};
use crate::mimeparser::SystemMessage;
use crate::param::Param;
use crate::securejoin::JoinerProgress;
use crate::tools::time;

/// Starts the securejoin protocol and creates a new `bobstate` table row.
///
/// The `chat_id` needs to be the ID of the 1:1 chat with Alice, this chat will be used
/// to exchange the SecureJoin handshake messages as well as for showing error messages.
///
/// # Bob - the joiner's side
/// ## Step 2 in the "Setup Contact protocol", section 2.1 of countermitm 0.10.0
///
/// This currently aborts any other securejoin process if any did not yet complete.
pub async fn start_protocol(context: &Context, invite: QrInvite, chat_id: ChatId) -> Result<()> {
    let peer_verified =
        verify_sender_by_fingerprint(context, invite.fingerprint(), invite.contact_id()).await?;

    if peer_verified {
        // The scanned fingerprint matches Alice's key, we can proceed to step 4b.
        info!(context, "Taking securejoin protocol shortcut");
        send_handshake_message(context, &invite, chat_id, BobHandshakeMsg::RequestWithAuth).await?;

        // Mark 1:1 chat as verified already.
        crate::securejoin::bob::set_peer_verified(context, invite.contact_id(), chat_id, time())
            .await?;

        context.emit_event(EventType::SecurejoinJoinerProgress {
            contact_id: invite.contact_id(),
            progress: JoinerProgress::RequestWithAuthSent.into(),
        });
    } else {
        send_handshake_message(context, &invite, chat_id, BobHandshakeMsg::Request).await?;

        insert_new_db_entry(context, invite.clone(), chat_id).await?;
    }
    Ok(())
}

/// Inserts a new entry in the bobstate table.
///
/// Returns the ID of the newly inserted entry.
async fn insert_new_db_entry(context: &Context, invite: QrInvite, chat_id: ChatId) -> Result<i64> {
    context
        .sql
        .insert(
            "INSERT INTO bobstate (invite, next_step, chat_id) VALUES (?, ?, ?);",
            (invite, 0, chat_id),
        )
        .await
}

/// Sends the requested handshake message to Alice.
pub(crate) async fn send_handshake_message(
    context: &Context,
    invite: &QrInvite,
    chat_id: ChatId,
    step: BobHandshakeMsg,
) -> Result<()> {
    let mut msg = Message {
        viewtype: Viewtype::Text,
        text: step.body_text(invite),
        hidden: true,
        ..Default::default()
    };
    msg.param.set_cmd(SystemMessage::SecurejoinMessage);

    // Sends the step in Secure-Join header.
    msg.param.set(Param::Arg, step.securejoin_header(invite));

    match step {
        BobHandshakeMsg::Request => {
            // Sends the Secure-Join-Invitenumber header in mimefactory.rs.
            msg.param.set(Param::Arg2, invite.invitenumber());
            msg.force_plaintext();
        }
        BobHandshakeMsg::RequestWithAuth => {
            // Sends the Secure-Join-Auth header in mimefactory.rs.
            msg.param.set(Param::Arg2, invite.authcode());
            msg.param.set_int(Param::GuaranteeE2ee, 1);

            // Sends our own fingerprint in the Secure-Join-Fingerprint header.
            let bob_fp = load_self_public_key(context).await?.dc_fingerprint();
            msg.param.set(Param::Arg3, bob_fp.hex());

            // Sends the grpid in the Secure-Join-Group header.
            //
            // `Secure-Join-Group` header is deprecated,
            // but old Delta Chat core requires that Alice receives it.
            //
            // Previous Delta Chat core also sent `Secure-Join-Group` header
            // in `vg-request` messages,
            // but it was not used on the receiver.
            if let QrInvite::Group { ref grpid, .. } = invite {
                msg.param.set(Param::Arg4, grpid);
            }
        }
    };

    chat::send_msg(context, chat_id, &mut msg).await?;
    Ok(())
}

/// Identifies the SecureJoin handshake messages Bob can send.
pub(crate) enum BobHandshakeMsg {
    /// vc-request or vg-request
    Request,
    /// vc-request-with-auth or vg-request-with-auth
    RequestWithAuth,
}

impl BobHandshakeMsg {
    /// Returns the text to send in the body of the handshake message.
    ///
    /// This text has no significance to the protocol, but would be visible if users see
    /// this email message directly, e.g. when accessing their email without using
    /// DeltaChat.
    fn body_text(&self, invite: &QrInvite) -> String {
        format!("Secure-Join: {}", self.securejoin_header(invite))
    }

    /// Returns the `Secure-Join` header value.
    ///
    /// This identifies the step this message is sending information about.  Most protocol
    /// steps include additional information into other headers, see
    /// [`send_handshake_message`] for these.
    fn securejoin_header(&self, invite: &QrInvite) -> &'static str {
        match self {
            Self::Request => match invite {
                QrInvite::Contact { .. } => "vc-request",
                QrInvite::Group { .. } => "vg-request",
            },
            Self::RequestWithAuth => match invite {
                QrInvite::Contact { .. } => "vc-request-with-auth",
                QrInvite::Group { .. } => "vg-request-with-auth",
            },
        }
    }
}
