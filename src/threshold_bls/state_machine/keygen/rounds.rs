use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{
    ShamirSecretSharing, VerifiableSS,
};
use curv::elliptic::curves::*;
use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, P2PMsgs, Store};
use round_based::Msg;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::threshold_bls::party_i;

pub struct Round0 {
    pub party_i: u16,
    pub t: u16,
    pub n: u16,
}

impl Round0 {
    pub fn proceed<O>(self, mut output: O) -> Result<Round1>
    where
        O: Push<Msg<party_i::KeyGenComm>>,
    {
        let keys = party_i::Keys::phase1_create(self.party_i - 1);
        let (comm, decom) = keys.phase1_broadcast();
        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: comm.clone(),
        });
        Ok(Round1 {
            keys,
            comm,
            decom,
            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round1 {
    keys: party_i::Keys,
    comm: party_i::KeyGenComm,
    decom: party_i::KeyGenDecom,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round1 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<party_i::KeyGenComm>,
        mut output: O,
    ) -> Result<Round2>
    where
        O: Push<Msg<party_i::KeyGenDecom>>,
    {
        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: self.decom.clone(),
        });
        Ok(Round2 {
            keys: self.keys,
            received_comm: input.into_vec_including_me(self.comm),
            decom: self.decom.clone(),

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        false
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<party_i::KeyGenComm>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

pub struct Round2 {
    keys: party_i::Keys,
    received_comm: Vec<party_i::KeyGenComm>,
    decom: party_i::KeyGenDecom,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round2 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<party_i::KeyGenDecom>,
        mut output: O,
    ) -> Result<Round3>
    where
        O: Push<Msg<(VerifiableSS<Bls12_381_2>, Scalar<Bls12_381_2>)>>,
    {
        let params = ShamirSecretSharing {
            threshold: self.t.into(),
            share_count: self.n.into(),
        };
        let received_decom = input.into_vec_including_me(self.decom);
        let (vss_scheme, secret_shares, index) = self
            .keys
            .phase1_verify_com_phase2_distribute(&params, &received_decom, &self.received_comm)
            .map_err(ProceedError::Round2VerifyCommitments)?;
        for (i, share) in secret_shares.iter().enumerate() {
            if i + 1 == usize::from(self.party_i) {
                continue;
            }

            output.push(Msg {
                sender: self.party_i,
                receiver: Some(i as u16 + 1),
                body: (vss_scheme.clone(), share.clone()),
            })
        }

        Ok(Round3 {
            keys: self.keys,

            y_vec: received_decom.into_iter().map(|d| d.y_i).collect(),

            index,
            own_vss: vss_scheme,
            own_share: secret_shares[usize::from(self.party_i - 1)].clone(),

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<party_i::KeyGenDecom>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

pub struct Round3 {
    keys: party_i::Keys,

    y_vec: Vec<Point<Bls12_381_2>>,

    index: u16,
    own_vss: VerifiableSS<Bls12_381_2>,
    own_share: Scalar<Bls12_381_2>,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round3 {
    pub fn proceed<O>(
        self,
        input: P2PMsgs<(VerifiableSS<Bls12_381_2>, Scalar<Bls12_381_2>)>,
        mut output: O,
    ) -> Result<Round4>
    where
        O: Push<Msg<DLogProof<Bls12_381_2>>>,
    {
        let params = ShamirSecretSharing {
            threshold: self.t.into(),
            share_count: self.n.into(),
        };
        let (vss_schemes, party_shares): (Vec<_>, Vec<_>) = input
            .into_vec_including_me((self.own_vss, self.own_share))
            .into_iter()
            .unzip();

        let (shared_keys, dlog_proof) = self
            .keys
            .phase2_verify_vss_construct_keypair_prove_dlog(
                &params,
                &self.y_vec,
                &party_shares,
                &vss_schemes,
                self.index + 1,
            )
            .map_err(ProceedError::Round3VerifyVssConstruct)?;

        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: dlog_proof.clone(),
        });

        Ok(Round4 {
            shared_keys,
            own_dlog_proof: dlog_proof,

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(
        i: u16,
        n: u16,
    ) -> Store<P2PMsgs<(VerifiableSS<Bls12_381_2>, Scalar<Bls12_381_2>)>> {
        containers::P2PMsgsStore::new(i, n)
    }
}

pub struct Round4 {
    shared_keys: party_i::SharedKeys,
    own_dlog_proof: DLogProof<Bls12_381_2>,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round4 {
    pub fn proceed(self, input: BroadcastMsgs<DLogProof<Bls12_381_2>>) -> Result<LocalKey> {
        let params = ShamirSecretSharing {
            threshold: self.t.into(),
            share_count: self.n.into(),
        };
        let dlog_proofs = input.into_vec_including_me(self.own_dlog_proof);
        party_i::Keys::verify_dlog_proofs(&params, &dlog_proofs)
            .map_err(ProceedError::Round4VerifyDLogProof)?;
        let vk_vec = dlog_proofs.into_iter().map(|p| p.pk).collect();
        Ok(LocalKey {
            shared_keys: self.shared_keys,
            vk_vec,

            i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<DLogProof<Bls12_381_2>>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

/// Local secret obtained by party after [keygen](super::Keygen) protocol is completed
#[derive(Clone, Serialize, Deserialize)]
pub struct LocalKey {
    pub(in crate::threshold_bls::state_machine) shared_keys: party_i::SharedKeys,
    pub(in crate::threshold_bls::state_machine) vk_vec: Vec<Point<Bls12_381_2>>,

    pub(in crate::threshold_bls::state_machine) i: u16,
    pub(in crate::threshold_bls::state_machine) t: u16,
    pub(in crate::threshold_bls::state_machine) n: u16,
}

impl LocalKey {
    pub fn new(
        t: u16,
        n: u16,
        sk_i: Scalar<Bls12_381_2>,
        vk_vec: Vec<Point<Bls12_381_2>>,
        tpk: Point<Bls12_381_2>,
    ) -> Result<Self, InvalidLocalKey> {
        if n < 2 {
            return Err(InvalidLocalKey::TooFewParties { n });
        }
        if !(1 <= t && t + 1 <= n) {
            return Err(InvalidLocalKey::ThresholdNotInRange { t, n });
        }
        let vk_i = Point::generator() * &sk_i;
        let i = (1..)
            .zip(&vk_vec)
            .find_map(|(j, vk_j)| if vk_i == *vk_j { Some(j) } else { None })
            .ok_or(InvalidLocalKey::VkDoesntIncludeSk)?;

        Ok(LocalKey {
            shared_keys: party_i::SharedKeys {
                index: i - 1,
                params: ShamirSecretSharing {
                    threshold: t,
                    share_count: n,
                },
                vk: tpk,
                sk_i,
            },
            vk_vec,

            i,
            t,
            n,
        })
    }
    /// Public key of secret shared between parties
    pub fn public_key(&self) -> Point<Bls12_381_2> {
        self.shared_keys.vk.clone()
    }
}

// Errors

type Result<T, E = ProceedError> = std::result::Result<T, E>;

/// Proceeding protocol error
///
/// Subset of [keygen errors](enum@super::Error) that can occur at protocol proceeding (i.e. after
/// every message was received and pre-validated).
#[derive(Debug, Error)]
pub enum ProceedError {
    #[error("round 2: verify commitments: {0:?}")]
    Round2VerifyCommitments(crate::Error),
    #[error("round 3: verify vss construction: {0:?}")]
    Round3VerifyVssConstruct(crate::Error),
    #[error("round 4: verify dlog proof: {0:?}")]
    Round4VerifyDLogProof(crate::Error),
}

/// Construction [LocalKey] error
#[derive(Debug, Error)]
pub enum InvalidLocalKey {
    #[error("threshold not in range t={}, range=[1,{}]", t, n-1)]
    ThresholdNotInRange { t: u16, n: u16 },
    #[error("too few parties: {n}")]
    TooFewParties { n: u16 },
    #[error("vk_vec doesn't include vk_i = sk_i G")]
    VkDoesntIncludeSk,
}
