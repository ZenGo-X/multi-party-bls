#![allow(non_snake_case)]

use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::*;
use curv::BigInt;
use sha2::Sha256;

pub mod party_i;
#[cfg(any(test, feature = "dev"))]
pub mod test;

pub fn h1(index: usize, pk_vec: &[Point<Bls12_381_2>]) -> BigInt {
    let mut pk = vec![&pk_vec[index]];
    let pk_ref_vec: Vec<_> = pk_vec.iter().map(|k| k).collect();
    pk.extend_from_slice(&pk_ref_vec[..]);
    Sha256::new().chain_points(pk).result_bigint()
}
