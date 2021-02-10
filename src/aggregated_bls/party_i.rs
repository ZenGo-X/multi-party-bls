use curv::arithmetic::traits::Modulo;
use curv::elliptic::curves::bls12_381::g1::FE as FE1;
use curv::elliptic::curves::bls12_381::g1::GE as GE1;
use curv::elliptic::curves::bls12_381::g2::FE as FE2;
use curv::elliptic::curves::bls12_381::g2::GE as GE2;
use curv::elliptic::curves::bls12_381::Pair;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use curv::BigInt;

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

    pub fn batch_aggregate_bls(sig_vec: &[BLSSignature]) -> BLSSignature {
        let (head, tail) = sig_vec.split_at(1);
        BLSSignature {
            sigma: tail.iter().fold(head[0].sigma, |acc, x| acc + x.sigma),
        }
    }

    fn core_aggregate_verify(apk_vec: &[APK], msg_vec: &[&[u8]], sig: &BLSSignature) -> bool {
        assert!(apk_vec.len() >= 1);
        let product_c2 = Pair::compute_pairing(&sig.sigma, &GE2::generator());
        let vec_g1: Vec<GE1> = msg_vec.iter().map(|&x| GE1::hash_to_curve(&x)).collect();
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
        if {
            let mut tmp = msg_vec.to_vec();
            tmp.sort();
            tmp.dedup();
            tmp.len() != msg_vec.len()
        } {
            return false; // verification fails if there is a repeated message
        }
        Keys::core_aggregate_verify(apk_vec, msg_vec, sig)
    }
}
