#![allow(non_snake_case)]

use curv::elliptic::curves::bls12_381::{self, Pair};
use curv::elliptic::curves::*;

use ff_zeroize::Field;
use pairing_plus::bls12_381::Fq12;

/// Based on https://eprint.iacr.org/2018/483.pdf

#[derive(Clone, Debug)]
pub struct KeyPairG2 {
    Y: Point<Bls12_381_2>,
    x: Scalar<Bls12_381_2>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BLSSignature {
    pub sigma: Point<Bls12_381_1>,
}

impl KeyPairG2 {
    pub fn new() -> Self {
        let x = Scalar::random();
        let Y = Point::generator() * &x;
        KeyPairG2 { x, Y }
    }
}

impl BLSSignature {
    // compute sigma  = x H(m)
    pub fn sign(message: &[u8], keys: &KeyPairG2) -> Self {
        let H_m = Point::from_raw(bls12_381::g1::G1Point::hash_to_curve(message))
            .expect("hash_to_curve must return valid point");
        // Convert FE2 -> FE1
        let fe1_x = Scalar::from_raw(keys.x.clone().into_raw());
        BLSSignature {
            sigma: H_m * &fe1_x,
        }
    }

    // check e(H(m), Y) == e(sigma, g2)
    pub fn verify(&self, message: &[u8], pubkey: &Point<Bls12_381_2>) -> bool {
        let H_m = Point::from_raw(bls12_381::g1::G1Point::hash_to_curve(message))
            .expect("hash_to_curve must return valid point");
        let product =
            Pair::efficient_pairing_mul(&H_m, pubkey, &self.sigma, &(-Point::generator()));
        product.e == Fq12::one()
    }

    pub fn to_bytes(&self, compressed: bool) -> Vec<u8> {
        self.sigma.to_bytes(compressed).to_vec()
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
