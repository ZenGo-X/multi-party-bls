use curv::elliptic::curves::bls12_381::{self, Pair};
use curv::elliptic::curves::*;

use crate::aggregated_bls::h1;
use crate::basic_bls::BLSSignature;

/// This is an implementation of BDN18 [https://eprint.iacr.org/2018/483.pdf]
/// protocol 3.1 (MSP): pairing-based multi-signature with public-key aggregation
#[derive(PartialEq, Clone, Debug)]
pub struct Keys {
    pub sk_i: Scalar<Bls12_381_2>,
    pub pk_i: Point<Bls12_381_2>,
    pub party_index: usize,
}

pub type APK = Point<Bls12_381_2>;
pub type SIG = Point<Bls12_381_1>;

impl Keys {
    pub fn new(index: usize) -> Self {
        let u = Scalar::random();
        let y = Point::generator() * &u;

        Keys {
            sk_i: u,
            pk_i: y,
            party_index: index,
        }
    }

    pub fn aggregate(pk_vec: &[Point<Bls12_381_2>]) -> APK {
        pk_vec
            .iter()
            .enumerate()
            .map(|(i, pk_i)| pk_i * Scalar::from_bigint(&h1(i, pk_vec)))
            .sum()
    }

    pub fn local_sign(&self, message: &[u8], pk_vec: &[Point<Bls12_381_2>]) -> SIG {
        let a_i = Scalar::from_bigint(&h1(self.party_index, pk_vec));
        let exp = a_i * &self.sk_i;
        // Convert FE2 -> FE1
        let exp = Scalar::from_raw(exp.into_raw());
        let h_0_m = Point::from_raw(bls12_381::g1::G1Point::hash_to_curve(message))
            .expect("hash_to_curve must return valid point");
        h_0_m * exp
    }

    pub fn combine_local_signatures(sigs: &[SIG]) -> BLSSignature {
        let sig_sum = sigs.iter().sum();
        BLSSignature { sigma: sig_sum }
    }

    pub fn verify(signature: &BLSSignature, message: &[u8], apk: &APK) -> bool {
        signature.verify(message, apk)
    }

    pub fn batch_aggregate_bls(sig_vec: &[BLSSignature]) -> BLSSignature {
        BLSSignature {
            sigma: sig_vec.iter().map(|s| &s.sigma).sum(),
        }
    }

    fn core_aggregate_verify(apk_vec: &[APK], msg_vec: &[&[u8]], sig: &BLSSignature) -> bool {
        assert!(!apk_vec.is_empty());
        let product_c2 = Pair::compute_pairing(&sig.sigma, &Point::generator());
        let vec_g1: Vec<Point<Bls12_381_1>> = msg_vec
            .iter()
            .map(|&x| {
                Point::from_raw(bls12_381::g1::G1Point::hash_to_curve(x))
                    .expect("hash_to_curve must return valid point")
            })
            .collect();
        let vec: Vec<_> = vec_g1.iter().zip(apk_vec.iter()).collect();
        let (head, tail) = vec.split_at(1);
        let product_c1 = tail
            .iter()
            .fold(Pair::compute_pairing(head[0].0, head[0].1), |acc, x| {
                acc.add_pair(&Pair::compute_pairing(x.0, x.1))
            });
        product_c1.e == product_c2.e
    }

    pub fn aggregate_verify(apk_vec: &[APK], msg_vec: &[&[u8]], sig: &BLSSignature) -> bool {
        assert!(apk_vec.len() == msg_vec.len());
        let res = {
            let mut tmp = msg_vec.to_vec();
            tmp.sort();
            tmp.dedup();
            tmp.len() != msg_vec.len()
        }; if res {
            return false; // verification fails if there is a repeated message
        }
        Keys::core_aggregate_verify(apk_vec, msg_vec, sig)
    }
}
