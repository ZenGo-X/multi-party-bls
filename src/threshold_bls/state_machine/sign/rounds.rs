use curv::elliptic::curves::bls12_381::g1::GE as GE1;
use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, Store};
use round_based::Msg;
use thiserror::Error;

use crate::basic_bls::BLSSignature;
use crate::threshold_bls::party_i;
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
    message: GE1,

    partial_sig: party_i::PartialSignature,
}

impl Round1 {
    pub fn proceed(
        self,
        input: BroadcastMsgs<(u16, party_i::PartialSignature)>,
    ) -> Result<(GE1, BLSSignature)> {
        let (indexes, sigs): (Vec<_>, Vec<_>) = input
            .into_vec_including_me((self.key.i, self.partial_sig))
            .into_iter()
            .unzip();

        let mut vk_vec = vec![];
        for (party_i, &keygen_i) in indexes.iter().enumerate() {
            if keygen_i == 0 || keygen_i > self.key.n {
                return Err(ProceedError::PartySentOutOfRangeIndex {
                    who: party_i as u16 + 1,
                    claimed_index: keygen_i,
                });
            }
            vk_vec.push(self.key.vk_vec[usize::from(keygen_i) - 1])
        }

        let indexes: Vec<_> = indexes.into_iter().map(|i| usize::from(i) - 1).collect();
        let sig = self
            .key
            .shared_keys
            .combine(&vk_vec, &sigs, self.message, &indexes)
            .map_err(ProceedError::PartialSignatureVerification)?;
        Ok((self.message, sig))
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(
        i: u16,
        n: u16,
    ) -> Store<BroadcastMsgs<(u16, party_i::PartialSignature)>> {
        containers::BroadcastMsgsStore::new(i, n)
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

type Result<T> = std::result::Result<T, ProceedError>;
