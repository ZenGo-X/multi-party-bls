use serde::{Deserialize, Serialize};

use sha2::Sha256;

use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::*;
use curv::BigInt;

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
    pub a1: Point<Bls12_381_1>,
    pub a2: Point<Bls12_381_2>,
    pub z: BigInt,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ECDDHStatement {
    pub g1: Point<Bls12_381_1>,
    pub h1: Point<Bls12_381_1>,
    pub g2: Point<Bls12_381_2>,
    pub h2: Point<Bls12_381_2>,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ECDDHWitness {
    pub x: BigInt,
}

impl ECDDHProof {
    pub fn prove(w: &ECDDHWitness, delta: &ECDDHStatement) -> ECDDHProof {
        let s1 = Scalar::random();
        let a1 = &delta.g1 * &s1;
        // Convert FE1 -> FE2
        let s2 = Scalar::from_raw(s1.into_raw());
        let a2 = &delta.g2 * &s2;
        let e = Sha256::new()
            .chain_points([&delta.g1, &delta.h1])
            .chain_points([&delta.g2, &delta.h2])
            .chain_point(&a1)
            .chain_point(&a2)
            .result_bigint();
        let z = s2.to_bigint() + e * &w.x;
        ECDDHProof { a1, a2, z }
    }

    pub fn verify(&self, delta: &ECDDHStatement) -> bool {
        let e = Sha256::new()
            .chain_points([&delta.g1, &delta.h1])
            .chain_points([&delta.g2, &delta.h2])
            .chain_point(&self.a1)
            .chain_point(&self.a2)
            .result_bigint();
        let z_g1 = &delta.g1 * Scalar::from_bigint(&self.z);
        let z_g2 = &delta.g2 * Scalar::from_bigint(&self.z);

        let a1_plus_e_h1 = &self.a1 + &(&delta.h1 * Scalar::from_bigint(&e));
        let a2_plus_e_h2 = &self.a2 + &(&delta.h2 * Scalar::from_bigint(&e));
        z_g1 == a1_plus_e_h1 && z_g2 == a2_plus_e_h2
    }
}

#[cfg(test)]
mod tests {
    use curv::elliptic::curves::*;

    use super::*;

    #[test]
    fn test_ecddh_proof() {
        let x1 = Scalar::random();
        let x2 = Scalar::from_raw(x1.clone().into_raw());

        let g1 = Point::generator();
        let g2 = Point::base_point2();
        let h1 = g1 * &x1;
        let h2 = g2 * &x2;

        let delta = ECDDHStatement {
            g1: g1.to_point(),
            h1,
            g2: g2.clone(),
            h2,
        };
        let w = ECDDHWitness { x: x1.to_bigint() };
        let proof = ECDDHProof::prove(&w, &delta);
        assert!(proof.verify(&delta));
    }

    #[test]
    fn test_bad_ecddh_proof() {
        let x1 = Scalar::random();
        let x2 = Scalar::from_raw(x1.clone().into_raw());

        let g1 = Point::generator();
        let g2 = Point::base_point2();
        let h1 = g1 * &x1;
        let h2 = g2 * (&x2 + Scalar::from(1));

        let delta = ECDDHStatement {
            g1: g1.to_point(),
            h1,
            g2: g2.clone(),
            h2,
        };
        let w = ECDDHWitness { x: x1.to_bigint() };
        let proof = ECDDHProof::prove(&w, &delta);
        assert!(!proof.verify(&delta));
    }
}
