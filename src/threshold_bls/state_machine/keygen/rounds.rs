use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{
    ShamirSecretSharing, VerifiableSS,
};
use curv::elliptic::curves::bls12_381::g2::FE as FE2;
use curv::elliptic::curves::bls12_381::g2::GE as GE2;
use round_based::containers::{self, BroadcastMsgs, P2PMsgs, Store};
use round_based::{IsCritical, Msg};

use crate::threshold_bls::party_i;

pub struct Round0 {
    pub party_i: u16,
    pub t: u16,
    pub n: u16,
}

impl Round0 {
    pub fn proceed(self, output: &mut Vec<Msg<M>>) -> Result<Round1> {
        let keys = party_i::Keys::phase1_create(usize::from(self.party_i) - 1);
        let (comm, decom) = keys.phase1_broadcast();
        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: M::Round1(comm.clone()),
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
    pub fn proceed(
        self,
        input: BroadcastMsgs<party_i::KeyGenComm>,
        output: &mut Vec<Msg<M>>,
    ) -> Result<Round2> {
        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: M::Round2(self.decom.clone()),
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
    pub fn proceed(
        self,
        input: BroadcastMsgs<party_i::KeyGenDecom>,
        output: &mut Vec<Msg<M>>,
    ) -> Result<Round3> {
        let params = ShamirSecretSharing {
            threshold: self.t.into(),
            share_count: self.n.into(),
        };
        let received_decom = input.into_vec_including_me(self.decom);
        let (vss_scheme, secret_shares, index) = self
            .keys
            .phase1_verify_com_phase2_distribute(&params, &received_decom, &self.received_comm)
            .map_err(Error::Round2VerifyCommitments)?;
        for (i, share) in secret_shares.iter().enumerate() {
            if i + 1 == usize::from(self.party_i) {
                continue;
            }

            output.push(Msg {
                sender: self.party_i,
                receiver: Some(i as u16 + 1),
                body: M::Round3((vss_scheme.clone(), share.clone())),
            })
        }

        Ok(Round3 {
            keys: self.keys,

            y_vec: received_decom.into_iter().map(|d| d.y_i).collect(),

            index,
            own_vss: vss_scheme,
            own_share: secret_shares[usize::from(self.party_i - 1)],

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

    y_vec: Vec<GE2>,

    index: usize,
    own_vss: VerifiableSS<GE2>,
    own_share: FE2,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round3 {
    pub fn proceed(
        self,
        input: P2PMsgs<(VerifiableSS<GE2>, FE2)>,
        output: &mut Vec<Msg<M>>,
    ) -> Result<Round4> {
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
                &(self.index + 1),
            )
            .map_err(Error::Round3VerifyVssConstruct)?;

        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: M::Round4(dlog_proof.clone()),
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
    pub fn expects_messages(i: u16, n: u16) -> Store<P2PMsgs<(VerifiableSS<GE2>, FE2)>> {
        containers::P2PMsgsStore::new(i, n)
    }
}

pub struct Round4 {
    shared_keys: party_i::SharedKeys,
    own_dlog_proof: DLogProof<GE2>,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round4 {
    pub fn proceed(self, input: BroadcastMsgs<DLogProof<GE2>>) -> Result<LocalKey> {
        let params = ShamirSecretSharing {
            threshold: self.t.into(),
            share_count: self.n.into(),
        };
        let dlog_proofs = input.into_vec_including_me(self.own_dlog_proof);
        party_i::Keys::verify_dlog_proofs(&params, &dlog_proofs)
            .map_err(Error::Round4VerifyDLogProof)?;
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
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<DLogProof<GE2>>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

pub enum R {
    Round0(Round0),
    Round1(Round1),
    Round2(Round2),
    Round3(Round3),
    Round4(Round4),
    Final(LocalKey),
    Gone,
}

#[derive(Clone)]
pub struct LocalKey {
    pub(in crate::threshold_bls::state_machine) shared_keys: party_i::SharedKeys,
    pub(in crate::threshold_bls::state_machine) vk_vec: Vec<GE2>,

    pub(in crate::threshold_bls::state_machine) i: u16,
    pub(in crate::threshold_bls::state_machine) t: u16,
    pub(in crate::threshold_bls::state_machine) n: u16,
}

// Messages

#[derive(Clone, Debug)]
pub enum M {
    Round1(party_i::KeyGenComm),
    Round2(party_i::KeyGenDecom),
    Round3((VerifiableSS<GE2>, FE2)),
    Round4(DLogProof<GE2>),
}

// Errors

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Round2VerifyCommitments(crate::Error),
    Round3VerifyVssConstruct(crate::Error),
    Round4VerifyDLogProof(crate::Error),

    /// Too few parties (`n < 2`)
    TooFewParties,
    /// Threshold value `t` is not in range `[1; n-1]`
    InvalidThreshold,
    /// Party index `i` is not in range `[1; n]`
    InvalidPartyIndex,

    HandleMessage(containers::StoreErr),
    RetrieveRoundMessages(containers::StoreErr),
    ReceivedOutOfOrderMessage {
        current_round: u16,
        msg_round: u16,
    },
    DoublePickResult,
}

impl IsCritical for Error {
    fn is_critical(&self) -> bool {
        true
    }
}
