#![allow(non_snake_case)]

use curv::elliptic::curves::bls12_381::g1::FE as FE1;
use curv::elliptic::curves::bls12_381::g1::GE as GE1;
use curv::elliptic::curves::bls12_381::g2::FE as FE2;
use curv::elliptic::curves::bls12_381::g2::GE as GE2;
use curv::elliptic::curves::bls12_381::Pair;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};

use ff_zeroize::Field;
use pairing_plus::bls12_381::{Fq12, G1Affine};
use pairing_plus::serdes::SerDes;

/// Based on https://eprint.iacr.org/2018/483.pdf

#[derive(Clone, Copy, Debug)]
pub struct KeyPairG2 {
    Y: GE2,
    x: FE2,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BLSSignature {
    pub sigma: GE1,
}

impl KeyPairG2 {
    pub fn new() -> Self {
        let x: FE2 = ECScalar::new_random();
        let Y = GE2::generator() * &x;
        KeyPairG2 { x, Y }
    }
}

impl BLSSignature {
    // compute sigma  = x H(m)
    pub fn sign(message: &[u8], keys: &KeyPairG2) -> Self {
        let H_m = GE1::hash_to_curve(message);
        let fe1_x: FE1 = ECScalar::from(&ECScalar::to_big_int(&keys.x));
        BLSSignature {
            sigma: H_m * &fe1_x,
        }
    }

    // check e(H(m), Y) == e(sigma, g2)
    pub fn verify(&self, message: &[u8], pubkey: &GE2) -> bool {
        let H_m = GE1::hash_to_curve(message);
        let product = Pair::efficient_pairing_mul(&H_m, pubkey, &self.sigma, &(-GE2::generator()));
        product.e == Fq12::one()
    }

    pub fn to_bytes(&self, compressed: bool) -> Vec<u8> {
        let mut pk = vec![];
        G1Affine::serialize(&self.sigma.get_element(), &mut pk, compressed)
            .expect("serialize to vec should always succeed");
        pk
    }
}

mod test {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    pub fn test_simple_bls() {
        let keypair = KeyPairG2::new();
        let Y = keypair.Y.clone();
        let message_bytes = [1, 2, 3, 4, 5];
        let signature = BLSSignature::sign(&message_bytes[..], &keypair);
        assert!(signature.verify(&message_bytes[..], &Y));
    }

    #[test]
    #[should_panic]
    pub fn test_bad_simple_bls() {
        let keypair = KeyPairG2::new();
        let Y = keypair.Y.clone();
        let message_bytes = [1, 2, 3, 4, 5];
        let signature = BLSSignature::sign(&message_bytes[..], &keypair);
        let message_bytes_corrupt = [0, 2, 3, 4, 5];
        assert!(signature.verify(&message_bytes_corrupt[..], &Y));
    }
}
