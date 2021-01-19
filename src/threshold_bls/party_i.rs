use crate::Error;

use curv::arithmetic::traits::*;

use curv::elliptic::curves::traits::*;

use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::BigInt;

use crate::basic_bls::BLSSignature;
use crate::threshold_bls::utilities::{ECDDHProof, ECDDHStatement, ECDDHWitness};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::ShamirSecretSharing;
use curv::elliptic::curves::bls12_381::g1::FE as FE1;
use curv::elliptic::curves::bls12_381::g1::GE as GE1;
use curv::elliptic::curves::bls12_381::g2::FE as FE2;
use curv::elliptic::curves::bls12_381::g2::GE as GE2;
use serde::{Deserialize, Serialize};

const SECURITY: usize = 256;

/// The protocol follows threshold GLOW signature from  [https://eprint.iacr.org/2020/096.pdf] section VIII.
/// In our protocol we assume dishonest majority. We adapt the DKG accordingly.
/// Specifically, as robustness in not achievable, we follow the design of optimistic DKG:
/// In it, we hope that all parties behave honestly, however, if a party misbehaves all other members
/// are able to detect it and re-run the protocol without the faulty party. This design principle is common to
/// real world applications.
/// Frost [https://eprint.iacr.org/2020/852.pdf]  and GG19 [https://eprint.iacr.org/2019/114.pdf] DKGs
/// are two implementations that follows this design. We picked GG19 (see section 4.1) as the paper
/// provides a full security proof for the DKG.
/// We removed the RSA modulus generation from the DKG as this is unrelated to threshold BLS and do not affect the security proof.
/// We note that the DKG can probably be biased to some extent, however, we do not find it concerning
/// for the threshold BLS application.

#[derive(Copy, PartialEq, Clone, Debug)]
pub struct Keys {
    pub u_i: FE2,
    pub y_i: GE2,
    pub party_index: usize,
}

#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenComm {
    pub com: BigInt,
}

#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenDecom {
    pub blind_factor: BigInt,
    pub y_i: GE2,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SharedKeys {
    pub index: usize,
    pub params: ShamirSecretSharing,
    pub vk: GE2,
    pub sk_i: FE2,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct PartialSignature {
    pub index: usize,
    pub sigma_i: GE1,
    pub ddh_proof: ECDDHProof,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Signature {
    pub sigma: GE1,
}

impl Keys {
    pub fn phase1_create(index: usize) -> Keys {
        let u: FE2 = ECScalar::new_random();
        let y = &ECPoint::generator() * &u;

        Keys {
            u_i: u,
            y_i: y,
            party_index: index,
        }
    }

    pub fn phase1_broadcast(&self) -> (KeyGenComm, KeyGenDecom) {
        let blind_factor = BigInt::sample(SECURITY);
        let com = HashCommitment::create_commitment_with_user_defined_randomness(
            &(self.y_i.bytes_compressed_to_big_int() + BigInt::from(self.party_index as u32)), // we add context to the hash function
            &blind_factor,
        );
        let bcm1 = KeyGenComm { com };
        let decm1 = KeyGenDecom {
            blind_factor,
            y_i: self.y_i.clone(),
        };
        (bcm1, decm1)
    }

    pub fn phase1_verify_com_phase2_distribute(
        &self,
        params: &ShamirSecretSharing,
        decom_vec: &Vec<KeyGenDecom>,
        bc1_vec: &Vec<KeyGenComm>,
    ) -> Result<(VerifiableSS<GE2>, Vec<FE2>, usize), Error> {
        // test length:
        if decom_vec.len() != params.share_count || bc1_vec.len() != params.share_count {
            return Err(Error::KeyGenMisMatchedVectors);
        }
        // test decommitments
        let correct_key_correct_decom_all = (0..bc1_vec.len())
            .map(|i| {
                HashCommitment::create_commitment_with_user_defined_randomness(
                    &(decom_vec[i].y_i.bytes_compressed_to_big_int() + BigInt::from(i as u32)),
                    &decom_vec[i].blind_factor,
                ) == bc1_vec[i].com
            })
            .all(|x| x == true);

        let (vss_scheme, secret_shares) =
            VerifiableSS::share(params.threshold, params.share_count, &self.u_i);

        match correct_key_correct_decom_all {
            true => Ok((vss_scheme, secret_shares, self.party_index.clone())),
            false => Err(Error::KeyGenBadCommitment),
        }
    }

    pub fn phase2_verify_vss_construct_keypair_prove_dlog(
        &self,
        params: &ShamirSecretSharing,
        y_vec: &Vec<GE2>,
        secret_shares_vec: &Vec<FE2>,
        vss_scheme_vec: &Vec<VerifiableSS<GE2>>,
        index: &usize,
    ) -> Result<(SharedKeys, DLogProof<GE2>), Error> {
        if y_vec.len() != params.share_count
            || secret_shares_vec.len() != params.share_count
            || vss_scheme_vec.len() != params.share_count
        {
            return Err(Error::KeyGenMisMatchedVectors);
        }

        let correct_ss_verify = (0..y_vec.len())
            .map(|i| {
                vss_scheme_vec[i]
                    .validate_share(&secret_shares_vec[i], *index)
                    .is_ok()
                    && vss_scheme_vec[i].commitments[0] == y_vec[i]
            })
            .all(|x| x == true);

        match correct_ss_verify {
            true => {
                let (head, tail) = y_vec.split_at(1);
                let y = tail.iter().fold(head[0], |acc, x| acc + x);
                let x_i = secret_shares_vec.iter().fold(FE2::zero(), |acc, x| acc + x);
                let dlog_proof = DLogProof::prove(&x_i);
                Ok((
                    SharedKeys {
                        index: self.party_index,
                        params: params.clone(),
                        vk: y,
                        sk_i: x_i,
                    },
                    dlog_proof,
                ))
            }
            false => Err(Error::KeyGenInvalidShare),
        }
    }

    pub fn verify_dlog_proofs(
        params: &ShamirSecretSharing,
        dlog_proofs_vec: &[DLogProof<GE2>],
    ) -> Result<(), Error> {
        if dlog_proofs_vec.len() != params.share_count {
            return Err(Error::KeyGenMisMatchedVectors);
        }
        let xi_dlog_verify = (0..dlog_proofs_vec.len())
            .map(|i| DLogProof::verify(&dlog_proofs_vec[i]).is_ok())
            .all(|x| x);

        if xi_dlog_verify {
            Ok(())
        } else {
            Err(Error::KeyGenDlogProofError)
        }
    }
}

impl SharedKeys {
    pub fn get_shared_pubkey(&self) -> GE2 {
        GE2::generator() * &self.sk_i
    }

    pub fn partial_sign(&self, x: &[u8]) -> (PartialSignature, GE1) {
        let H_x = GE1::hash_to_curve(x);
        let sk_bn = ECScalar::to_big_int(&self.sk_i);
        let sk_i_fe1: FE1 = ECScalar::from(&sk_bn);
        let sigma_i = &H_x * &sk_i_fe1;

        let w = ECDDHWitness { x: sk_bn };

        let delta = ECDDHStatement {
            g1: H_x.clone(),
            h1: sigma_i.clone(),
            g2: GE2::generator(),
            h2: self.get_shared_pubkey(),
        };
        let ddh_proof = ECDDHProof::prove(&w, &delta);
        assert!(ddh_proof.verify(&delta));

        (
            PartialSignature {
                index: self.index,
                sigma_i,
                ddh_proof,
            },
            H_x,
        )
    }

    pub fn combine(
        &self,
        vk_vec: &[GE2],
        partial_sigs_vec: &[PartialSignature],
        H_x: GE1,
        s: &[usize],
    ) -> Result<BLSSignature, Error> {
        if vk_vec.len() != partial_sigs_vec.len()
            || vk_vec.len() < self.params.threshold
            || s.len() < self.params.threshold
            || s.len() > self.params.share_count
        {
            return Err(Error::SigningMisMatchedVectors);
        }
        //verify ec_ddh proofs and signatures

        let partial_sigs_verify = (0..vk_vec.len())
            .map(|i| {
                let delta = ECDDHStatement {
                    g1: H_x.clone(),
                    h1: partial_sigs_vec[i].sigma_i.clone(),
                    g2: GE2::generator(),
                    h2: vk_vec[i],
                };

                partial_sigs_vec[i].ddh_proof.verify(&delta)
            })
            .all(|x| x);
        if partial_sigs_verify == false {
            return Err(Error::PartialSignatureVerificationError);
        }

        let (head, tail) = partial_sigs_vec.split_at(1);
        let sigma = tail[0..self.params.threshold].iter().fold(
            &head[0].sigma_i
                * &VerifiableSS::<GE1>::map_share_to_new_params(
                    &self.params,
                    head[0].index,
                    &s[0..self.params.threshold + 1],
                ),
            |acc, x| {
                acc + &x.sigma_i
                    * &VerifiableSS::<GE1>::map_share_to_new_params(
                        &self.params,
                        x.index,
                        &s[0..self.params.threshold + 1],
                    )
            },
        );

        return Ok(BLSSignature { sigma });
    }

    // check e(H(m), vk) == e(sigma, g2)
    pub fn verify(&self, sig: &BLSSignature, x: &[u8]) -> bool {
        sig.verify(x, &self.vk)
    }
}
