#![allow(non_snake_case)]

use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::bls12_381::g2::GE as GE2;
use curv::elliptic::curves::traits::ECScalar;
use curv::BigInt;

pub mod party_i;
#[cfg(any(test, feature = "dev"))]
pub mod test;

pub fn h1(index: usize, pk_vec: &[GE2]) -> BigInt {
    let mut pk = vec![&pk_vec[index]];
    let pk_ref_vec: Vec<_> = pk_vec.iter().map(|k| k).collect();
    pk.extend_from_slice(&pk_ref_vec[..]);
    let result1 = HSha256::create_hash_from_ge(&pk);
    result1.to_big_int()
}
