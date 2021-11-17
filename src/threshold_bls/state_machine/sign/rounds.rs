use std::collections::HashSet;
use std::convert::TryFrom;

use curv::elliptic::curves::*;
use round_based::containers::push::Push;
use round_based::Msg;
use thiserror::Error;

use crate::basic_bls::BLSSignature;
use crate::threshold_bls::party_i;
use crate::threshold_bls::party_i::SharedKeys;
use crate::threshold_bls::state_machine::keygen::LocalKey;

pub struct Round0 {
    pub key: LocalKey,
    pub message: Vec<u8>,

    pub i: u16,
    pub n: u16,
}

impl Round0 {
    pub fn proceed<O>(self, mut output: O) -> Result<Round1>
    where
        O: Push<Msg<(u16, party_i::PartialSignature)>>,
    {
        let (partial_sig, H_x) = self.key.shared_keys.partial_sign(&self.message);
        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: (self.key.i, partial_sig.clone()),
        });
        Ok(Round1 {
            key: self.key,
            message: H_x,
            partial_sig,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round1 {
    key: LocalKey,
    message: Point<Bls12_381_1>,

    partial_sig: party_i::PartialSignature,
}

impl Round1 {
    pub fn proceed(
        self,
        input: Vec<(u16, party_i::PartialSignature)>,
    ) -> Result<(Point<Bls12_381_1>, BLSSignature)> {
        let (indexes, sigs): (Vec<_>, Vec<_>) = input
            .into_iter()
            .chain(Some((self.key.i, self.partial_sig)))
            .unzip();

        let mut vk_vec = vec![];
        for (party_i, &keygen_i) in indexes.iter().enumerate() {
            if keygen_i == 0 || keygen_i > self.key.n {
                return Err(ProceedError::PartySentOutOfRangeIndex {
                    who: party_i as u16 + 1,
                    claimed_index: keygen_i,
                });
            }
            vk_vec.push(self.key.vk_vec[usize::from(keygen_i) - 1].clone())
        }

        let indexes: Vec<_> = indexes.into_iter().map(|i| i - 1).collect();
        let sig = self
            .key
            .shared_keys
            .combine(&vk_vec, &sigs, &self.message, &indexes)
            .map_err(ProceedError::PartialSignatureVerification)?;
        Ok((self.message, sig))
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(
        i: u16,
        n: u16,
        local_kay: &LocalKey,
        message_to_sign: Point<Bls12_381_1>,
    ) -> ReceiveFirstValidPartialSigs {
        ReceiveFirstValidPartialSigs {
            msgs: vec![],
            received_from: Default::default(),

            i,
            H_x: message_to_sign,
            vk_vec: local_kay.vk_vec.clone(),
            signers_n: n,
            secret_holders: local_kay.n,
            threshold: local_kay.t,
        }
    }
}

pub struct ReceiveFirstValidPartialSigs {
    msgs: Vec<(u16, party_i::PartialSignature)>,
    received_from: HashSet<u16>,

    i: u16,
    H_x: Point<Bls12_381_1>,
    vk_vec: Vec<Point<Bls12_381_2>>,
    signers_n: u16,
    secret_holders: u16,
    threshold: u16,
}

impl ReceiveFirstValidPartialSigs {
    pub fn messages_received(&self) -> usize {
        self.msgs.len()
    }

    pub fn messages_total(&self) -> u16 {
        self.threshold
    }
}

impl round_based::containers::MessageStore for ReceiveFirstValidPartialSigs {
    type M = (u16, party_i::PartialSignature);
    type Err = ReceivedPartialSigNotValid;
    type Output = Vec<(u16, party_i::PartialSignature)>;

    fn push_msg(&mut self, msg: Msg<Self::M>) -> Result<(), Self::Err> {
        if msg.sender == self.i {
            return Err(ReceivedPartialSigNotValid::ReceivedMyOwnShare);
        } else if msg.receiver.is_some() {
            return Err(ReceivedPartialSigNotValid::ExpectedBroadcast);
        } else if self.received_from.contains(&msg.sender) {
            return Err(ReceivedPartialSigNotValid::MsgOverwrite);
        } else if !(1 <= msg.body.0 && msg.body.0 <= self.secret_holders) {
            return Err(ReceivedPartialSigNotValid::PartyOriginalIndexOutOfRange {
                i: msg.body.0,
                n: self.secret_holders,
            });
        } else if !self.wants_more() {
            return Err(ReceivedPartialSigNotValid::TooManyMsgs);
        }

        let valid = SharedKeys::verify_partial_sig(
            &self.H_x,
            &msg.body.1,
            &self.vk_vec[usize::from(msg.body.0) - 1],
        )
        .is_ok();
        if !valid {
            return Err(ReceivedPartialSigNotValid::InvalidPartialSig);
        }
        if self.msgs.iter().any(|(i, _)| *i == msg.body.0) {
            return Err(ReceivedPartialSigNotValid::ShareOverwrite);
        }

        self.msgs.push(msg.body);
        self.received_from.insert(msg.sender);

        Ok(())
    }

    fn contains_msg_from(&self, sender: u16) -> bool {
        self.received_from.contains(&sender)
    }

    fn wants_more(&self) -> bool {
        self.msgs.len() < usize::from(self.threshold)
    }

    fn finish(self) -> Result<Self::Output, Self::Err> {
        if !self.wants_more() {
            Ok(self.msgs)
        } else {
            Err(ReceivedPartialSigNotValid::NotEnoughMsgs)
        }
    }

    fn blame(&self) -> (u16, Vec<u16>) {
        let left = u16::try_from(self.msgs.len()).unwrap() - self.threshold - 1;
        let didnt_send_message = (1..=self.signers_n)
            .filter(|i| !self.received_from.contains(i))
            .collect();
        (left, didnt_send_message)
    }
}

// Errors

/// Proceeding protocol error
///
/// Subset of [signing errors](enum@super::Error) that can occur at protocol proceeding (i.e. after
/// every message was received and pre-validated).
#[derive(Debug, Error)]
pub enum ProceedError {
    /// Every party needs to say which index it was using at keygen. This error is raised if
    /// `index == 0 || index > n` where n is a number of parties holding a key.
    #[error(
        "party {who} claimed its index at keygen was {claimed_index} which is not in range [1;n]"
    )]
    PartySentOutOfRangeIndex { who: u16, claimed_index: u16 },
    #[error("partial signatures verification: {0:?}")]
    PartialSignatureVerification(crate::Error),
}

#[derive(Debug, Error)]
pub enum ReceivedPartialSigNotValid {
    #[error("expected broadcast message, received p2p")]
    ExpectedBroadcast,
    #[error("received msg from the same sender twice")]
    MsgOverwrite,
    #[error("received the same signature share twice")]
    ShareOverwrite,
    #[error("party index out of range i={i}, n={n}")]
    PartyOriginalIndexOutOfRange { i: u16, n: u16 },
    #[error("partial sig proof is not valid")]
    InvalidPartialSig,
    #[error("not enough messages received to finish the protocol")]
    NotEnoughMsgs,
    #[error("enough messages received to construct a signature")]
    TooManyMsgs,
    #[error("received message from myself")]
    ReceivedMyOwnShare,
}

type Result<T, E = ProceedError> = std::result::Result<T, E>;
