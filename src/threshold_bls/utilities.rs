use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::bls12_381::g1::FE as FE1;
use curv::elliptic::curves::bls12_381::g1::GE as GE1;
use curv::elliptic::curves::bls12_381::g2::FE as FE2;
use curv::elliptic::curves::bls12_381::g2::GE as GE2;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use curv::BigInt;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// NIZK required for our threshold BLS:
/// This is a special case of the ec ddh proof from Curv:
/// [https://github.com/ZenGo-X/curv/blob/master/src/cryptographic_primitives/proofs/sigma_ec_ddh.rs]
/// In which {g1,h1} belong to G1 group and {g2,h2} belong to G2 group.
/// This special case is possible when |G1| = |G2|. i.e the order of G1 group is equal to the order
/// of G2 (there is a map between the groups). This is the case for BLS12-381.
/// This is a deviation from the GLOW-BLS protocol that degrades security from strong-unforgeability
/// to standard-unforgeability,as defined in "Threshold Signatures, Multisignatures and Blind Signatures Based on the Gap-Diffie-Hellman-Group Signature Scheme"

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ECDDHProof {
    pub a1: GE1,
    pub a2: GE2,
    pub z: BigInt,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ECDDHStatement {
    pub g1: GE1,
    pub h1: GE1,
    pub g2: GE2,
    pub h2: GE2,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ECDDHWitness {
    pub x: BigInt,
}

impl ECDDHProof {
    pub fn prove(w: &ECDDHWitness, delta: &ECDDHStatement) -> ECDDHProof {
        let mut s1 = FE1::new_random();
        let a1 = &delta.g1 * &s1;
        let s = s1.to_big_int();
        let mut s2: FE2 = ECScalar::from(&s);
        let a2 = &delta.g2 * &s2;
        let e = HSha256::create_hash(&[
            &delta.g1.bytes_compressed_to_big_int(),
            &delta.h1.bytes_compressed_to_big_int(),
            &delta.g2.bytes_compressed_to_big_int(),
            &delta.h2.bytes_compressed_to_big_int(),
            &a1.bytes_compressed_to_big_int(),
            &a2.bytes_compressed_to_big_int(),
        ]);
        let z = s + e * &w.x;
        s1.zeroize();
        s2.zeroize();
        ECDDHProof { a1, a2, z }
    }

    pub fn verify(&self, delta: &ECDDHStatement) -> bool {
        let e = HSha256::create_hash(&[
            &delta.g1.bytes_compressed_to_big_int(),
            &delta.h1.bytes_compressed_to_big_int(),
            &delta.g2.bytes_compressed_to_big_int(),
            &delta.h2.bytes_compressed_to_big_int(),
            &self.a1.bytes_compressed_to_big_int(),
            &self.a2.bytes_compressed_to_big_int(),
        ]);
        let z_g1 = &delta.g1 * &ECScalar::from(&self.z);
        let z_g2 = &delta.g2 * &ECScalar::from(&self.z);

        let a1_plus_e_h1 = &self.a1 + &(&delta.h1 * &ECScalar::from(&e));
        let a2_plus_e_h2 = &self.a2 + &(&delta.h2 * &ECScalar::from(&e));
        z_g1 == a1_plus_e_h1 && z_g2 == a2_plus_e_h2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curv::elliptic::curves::bls12_381::g1::FE as FE1;
    use curv::elliptic::curves::traits::{ECPoint, ECScalar};
    use curv::arithmetic::traits::*;

    #[test]
    fn test_ecddh_proof() {
        let x = FE1::new_random().to_big_int();
        let g1 = ECPoint::generator();
        let g2 = ECPoint::base_point2();
        let h1 = &g1 * &ECScalar::from(&x);
        let h2 = &g2 * &ECScalar::from(&x);

        let delta = ECDDHStatement { g1, h1, g2, h2 };
        let w = ECDDHWitness { x };
        let proof = ECDDHProof::prove(&w, &delta);
        assert!(proof.verify(&delta));
    }

    #[test]
    #[should_panic]
    fn test_bad_ecddh_proof() {
        let x = FE1::new_random().to_big_int();
        let g1 = ECPoint::generator();
        let g2 = ECPoint::base_point2();
        let h1 = &g1 * &ECScalar::from(&x);
        let h2 = &g2 * &ECScalar::from(&(&x + BigInt::one()));

        let delta = ECDDHStatement { g1, h1, g2, h2 };
        let w = ECDDHWitness { x };
        let proof = ECDDHProof::prove(&w, &delta);
        assert!(proof.verify(&delta));
    }
}
