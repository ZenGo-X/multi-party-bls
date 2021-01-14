use crate::aggregated_bls::h1;
use crate::basic_bls::BLSSignature;
use curv::arithmetic::traits::Modulo;
use curv::elliptic::curves::bls12_381::g1::FE as FE1;
use curv::elliptic::curves::bls12_381::g1::GE as GE1;
use curv::elliptic::curves::bls12_381::g2::FE as FE2;
use curv::elliptic::curves::bls12_381::g2::GE as GE2;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use curv::BigInt;

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
        let u: FE2 = ECScalar::new_random();
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
        let sig_sum = tail.iter().fold(head[0], |x, acc| x + acc);
        BLSSignature { sigma: sig_sum }
    }

    pub fn verify(signature: &BLSSignature, message: &[u8], apk: &APK) -> bool {
        signature.verify(message, apk)
    }
}
