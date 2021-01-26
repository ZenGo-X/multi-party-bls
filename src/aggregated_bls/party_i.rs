use std::collections::HashSet;

use curv::arithmetic::traits::Modulo;
use curv::elliptic::curves::bls12_381::g1::FE as FE1;
use curv::elliptic::curves::bls12_381::g1::GE as GE1;
use curv::elliptic::curves::bls12_381::g2::FE as FE2;
use curv::elliptic::curves::bls12_381::g2::GE as GE2;
use curv::elliptic::curves::bls12_381::Pair;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use curv::BigInt;
use pairing_plus::bls12_381::Bls12;
use pairing_plus::{CurveAffine, Engine};

use crate::aggregated_bls::h1;
use crate::basic_bls::BLSSignature;

/// This is an implementation of BDN18 [https://eprint.iacr.org/2018/483.pdf]
/// protocol 3.1 (MSP): pairing-based multi-signature with public-key aggregation
#[derive(Copy, PartialEq, Clone, Debug)]
pub struct Keys {
    pub sk_i: FE2,
    pub pk_i: GE2,
    pub party_index: usize,
}

pub type APK = GE2;
pub type SIG = GE1;

impl Keys {
    pub fn new(index: usize) -> Self {
        let u = ECScalar::new_random();
        let y = &ECPoint::generator() * &u;

        Keys {
            sk_i: u,
            pk_i: y,
            party_index: index,
        }
    }

    pub fn aggregate(pk_vec: &[GE2]) -> APK {
        let apk_plus_g = pk_vec.iter().fold(GE2::generator(), |acc, x| {
            let i = pk_vec.iter().position(|y| y == x).unwrap();
            acc + (pk_vec[i] * &ECScalar::from(&h1(i, pk_vec)))
        });
        apk_plus_g.sub_point(&GE2::generator().get_element())
    }

    pub fn local_sign(&self, message: &[u8], pk_vec: &[GE2]) -> SIG {
        let a_i = h1(self.party_index.clone(), pk_vec);
        let exp = BigInt::mod_mul(&a_i, &self.sk_i.to_big_int(), &FE1::q());
        let exp_fe1: FE1 = ECScalar::from(&exp);
        let h_0_m = GE1::hash_to_curve(message);
        h_0_m * exp_fe1
    }

    pub fn combine_local_signatures(sigs: &[SIG]) -> BLSSignature {
        let (head, tail) = sigs.split_at(1);
        let sig_sum = tail.iter().fold(head[0], |acc, x| acc + x);
        BLSSignature { sigma: sig_sum }
    }

    pub fn verify(signature: &BLSSignature, message: &[u8], apk: &APK) -> bool {
        signature.verify(message, apk)
    }

    fn efficient_pairing_loop(vec_g1: &[GE1], vec_g2: &[GE2]) -> Pair {
        let vec_g1_prep: Vec<_> = vec_g1.iter().map(|x| x.get_element().prepare()).collect();
        let vec_g2_prep: Vec<_> = vec_g2.iter().map(|x| x.get_element().prepare()).collect();
        let vec: Vec<_> = vec_g1_prep.iter().zip(vec_g2_prep.iter()).collect();
        Pair {
            e: Bls12::final_exponentiation(&Bls12::miller_loop(vec.iter())).unwrap(),
        }
    }

    pub fn aggregate_bls(sig_vec: &[BLSSignature]) -> BLSSignature {
        let (head, tail) = sig_vec.split_at(1);
        BLSSignature {
            sigma: tail.iter().fold(head[0].sigma, |acc, x| acc + x.sigma),
        }
    }

    fn core_aggregate_verify(apk_vec: &[APK], msg_vec: &[&[u8]], sig: &BLSSignature) -> bool {
        let product_c2 = Keys::efficient_pairing_loop(&[sig.sigma], &[GE2::generator()]);
        let vec_g1: Vec<GE1> = msg_vec.iter().map(|&x| GE1::hash_to_curve(&x)).collect();
        let product_c1 = Keys::efficient_pairing_loop(&vec_g1, &apk_vec);
        product_c1.e == product_c2.e
    }

    pub fn aggregate_verify(apk_vec: &[APK], msg_vec: &[&[u8]], sig: &BLSSignature) -> bool {
        if msg_vec.iter().collect::<HashSet<_>>().len() != msg_vec.len() {
            return false;
        };
        Keys::core_aggregate_verify(apk_vec, msg_vec, sig)
    }
}
