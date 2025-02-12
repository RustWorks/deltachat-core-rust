//! Secure-Join protocol state machine for Bob, the joiner-side.
//!
//! This module contains the state machine to run the Secure-Join handshake for Bob and does
//! not do any user interaction required by the protocol.  Instead the state machine
//! provides all the information to its driver so it can perform the correct interactions.
//!
//! The [`BobState`] is only directly used to initially create it when starting the
//! protocol.

use anyhow::Result;

use super::qrinvite::QrInvite;
use super::{encrypted_and_signed, verify_sender_by_fingerprint};
use crate::chat::{self, ChatId};
use crate::context::Context;
use crate::key::{load_self_public_key, DcKey};
use crate::message::{Message, Viewtype};
use crate::mimeparser::{MimeMessage, SystemMessage};
use crate::param::Param;
use crate::sql::Sql;
use crate::tools::time;

/// The stage of the [`BobState`] securejoin handshake protocol state machine.
///
/// This does not concern itself with user interactions, only represents what happened to
/// the protocol state machine from handling this message.
#[derive(Clone, Copy, Debug, Display)]
pub enum BobHandshakeStage {
    /// Step 2 completed: (vc|vg)-request message sent.
    RequestSent,
    /// Step 4 completed: (vc|vg)-request-with-auth message sent.
    RequestWithAuthSent,
}

/// The securejoin state kept while Bob is joining.
///
/// This is stored in the database and loaded from there using [`BobState::from_db`].  To
/// create a new one use [`BobState::start_protocol`].
///
/// This purposefully has nothing optional, the state is always fully valid.
///
/// # Conducting the securejoin handshake
///
/// The methods on this struct allow you to interact with the state and thus conduct the
/// securejoin handshake for Bob.  The methods only concern themselves with the protocol
/// state and explicitly avoid performing any user interactions required by securejoin.
/// This simplifies the concerns and logic required in both the callers and in the state
/// management.  The return values can be used to understand what user interactions need to
/// happen.
///
/// [`Bob`]: super::Bob
/// [`Bob::state`]: super::Bob::state
#[derive(Debug, Clone)]
pub struct BobState {
    /// Database primary key.
    id: i64,
    /// The QR Invite code.
    invite: QrInvite,
    /// The [`ChatId`] of the 1:1 chat with Alice, matching [`QrInvite::contact_id`].
    chat_id: ChatId,
}

impl BobState {
    /// Starts the securejoin protocol and creates a new [`BobState`].
    ///
    /// The `chat_id` needs to be the ID of the 1:1 chat with Alice, this chat will be used
    /// to exchange the SecureJoin handshake messages as well as for showing error messages.
    ///
    /// # Bob - the joiner's side
    /// ## Step 2 in the "Setup Contact protocol", section 2.1 of countermitm 0.10.0
    ///
    /// This currently aborts any other securejoin process if any did not yet complete.
    pub async fn start_protocol(
        context: &Context,
        invite: QrInvite,
        chat_id: ChatId,
    ) -> Result<(Self, BobHandshakeStage)> {
        let peer_verified =
            verify_sender_by_fingerprint(context, invite.fingerprint(), invite.contact_id())
                .await?;

        if peer_verified {
            // The scanned fingerprint matches Alice's key, we can proceed to step 4b.
            info!(context, "Taking securejoin protocol shortcut");
            send_handshake_message(context, &invite, chat_id, BobHandshakeMsg::RequestWithAuth)
                .await?;

            let stage = BobHandshakeStage::RequestWithAuthSent;

            // Mark 1:1 chat as verified already.
            crate::securejoin::bob::set_peer_verified(
                context,
                invite.contact_id(),
                chat_id,
                time(),
            )
            .await?;

            let state = Self {
                id: 0,
                invite,
                chat_id,
            };
            Ok((state, stage))
        } else {
            send_handshake_message(context, &invite, chat_id, BobHandshakeMsg::Request).await?;

            let stage = BobHandshakeStage::RequestSent;

            let id = Self::insert_new_db_entry(context, invite.clone(), chat_id).await?;
            let state = Self {
                id,
                invite,
                chat_id,
            };
            Ok((state, stage))
        }
    }

    /// Inserts a new entry in the bobstate table, deleting all previous entries.
    ///
    /// Returns the ID of the newly inserted entry.
    async fn insert_new_db_entry(
        context: &Context,
        invite: QrInvite,
        chat_id: ChatId,
    ) -> Result<i64> {
        context
            .sql
            .transaction(move |transaction| {
                // Delete everything and insert new row.
                transaction.execute("DELETE FROM bobstate;", ())?;
                transaction.execute(
                    "INSERT INTO bobstate (invite, next_step, chat_id) VALUES (?, ?, ?);",
                    (invite, 0, chat_id),
                )?;
                let id = transaction.last_insert_rowid();
                Ok(id)
            })
            .await
    }

    /// Load [`BobState`] from the database.
    pub async fn from_db(sql: &Sql) -> Result<Option<Self>> {
        // Because of how Self::start_protocol() updates the database we are currently
        // guaranteed to only have one row.
        sql.query_row_optional("SELECT id, invite, chat_id FROM bobstate;", (), |row| {
            let s = BobState {
                id: row.get(0)?,
                invite: row.get(1)?,
                chat_id: row.get(2)?,
            };
            Ok(s)
        })
        .await
    }

    /// Returns the [`QrInvite`] used to create this [`BobState`].
    pub fn invite(&self) -> &QrInvite {
        &self.invite
    }

    /// Returns the [`ChatId`] of the 1:1 chat with the inviter (Alice).
    pub fn alice_chat(&self) -> ChatId {
        self.chat_id
    }

    /// Deletes this [`BobState`] from the database
    /// because the joining process has finished.
    async fn terminate(&self, sql: &Sql) -> Result<()> {
        sql.execute("DELETE FROM bobstate WHERE id=?", (self.id,))
            .await?;
        Ok(())
    }

    /// Handles {vc,vg}-auth-required message of the securejoin handshake for Bob.
    ///
    /// Returns `true` if the message was used for this handshake, `false` otherwise.
    pub(crate) async fn handle_auth_required(
        &mut self,
        context: &Context,
        mime_message: &MimeMessage,
    ) -> Result<bool> {
        info!(
            context,
            "Bob Step 4 - handling {{vc,vg}}-auth-required message."
        );
        if !encrypted_and_signed(context, mime_message, self.invite.fingerprint()) {
            self.terminate(&context.sql).await?;
            return Ok(false);
        }
        if !verify_sender_by_fingerprint(
            context,
            self.invite.fingerprint(),
            self.invite.contact_id(),
        )
        .await?
        {
            self.terminate(&context.sql).await?;
            return Ok(false);
        }
        info!(context, "Fingerprint verified.",);

        self.terminate(&context.sql).await?;
        self.send_handshake_message(context, BobHandshakeMsg::RequestWithAuth)
            .await?;
        Ok(true)
    }

    /// Sends the requested handshake message to Alice.
    ///
    /// This takes care of adding the required headers for the step.
    async fn send_handshake_message(&self, context: &Context, step: BobHandshakeMsg) -> Result<()> {
        send_handshake_message(context, &self.invite, self.chat_id, step).await
    }
}

/// Sends the requested handshake message to Alice.
///
/// Same as [`BobState::send_handshake_message`] but this variation allows us to send this
/// message before we create the state in [`BobState::start_protocol`].
async fn send_handshake_message(
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
enum BobHandshakeMsg {
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
    /// [`BobState::send_handshake_message`] for these.
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
