use crate::basic_bls::BLSSignature;
use crate::threshold_bls::party_i::Keys;
use crate::threshold_bls::party_i::SharedKeys;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::ShamirSecretSharing;
use curv::elliptic::curves::bls12_381::g2::FE;
use curv::elliptic::curves::bls12_381::{g1::GE as GE1, g2::GE as GE2};
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use pairing_plus::CurveProjective;

#[test]
fn test_keygen_t1_n2() {
    keygen_t_n_parties(1, 2);
}

#[test]
fn test_keygen_t2_n3() {
    keygen_t_n_parties(2, 3);
}

// 2 out of 2
#[test]
fn test_sign_n2_t1_tprime2() {
    let message = vec![100, 101, 102, 103];
    let signatories: Vec<usize> = vec![0, 1];
    sign(&message[..], 1, 2, &signatories[..], None);
}

// 3 out of 3
#[test]
fn test_sign_n3_t2_tprime3() {
    let message = vec![100, 101, 102, 103];
    let signatories: Vec<usize> = vec![0, 1, 2];
    sign(&message[..], 2, 3, &signatories[..], None);
}

// 3 out of 5 with 4 signatories
#[test]
fn test_sign_n5_t2_tprime4() {
    let message = [100, 101, 102, 103];
    let signatories: Vec<usize> = vec![0, 2, 3, 4];
    sign(&message[..], 2, 5, &signatories[..], None);
}

// 5 out of 8 with 6 signatories
#[test]
fn test_sign_n8_t4_tprime6() {
    let message = vec![100, 101, 102, 103];
    let signatories: Vec<usize> = vec![0, 1, 2, 4, 6, 7];
    sign(&message[..], 4, 8, &signatories[..], None);
}

pub fn keygen_t_n_parties(t: usize, n: usize) -> (Vec<SharedKeys>, Vec<GE2>) {
    let parames = ShamirSecretSharing {
        threshold: t,
        share_count: n,
    };
    let party_keys_vec = (0..n)
        .map(|i| Keys::phase1_create(i))
        .collect::<Vec<Keys>>();

    let (bc1_vec, decom_vec): (Vec<_>, Vec<_>) =
        party_keys_vec.iter().map(|k| k.phase1_broadcast()).unzip();

    let y_vec = (0..n).map(|i| decom_vec[i].y_i).collect::<Vec<GE2>>();

    let mut vss_scheme_vec = Vec::new();
    let mut secret_shares_vec = Vec::new();
    let mut index_vec = Vec::new();

    let vss_result: Vec<_> = party_keys_vec
        .iter()
        .map(|k| {
            k.phase1_verify_com_phase2_distribute(&parames, &decom_vec, &bc1_vec)
                .expect("")
        })
        .collect();

    for (vss_scheme, secret_shares, index) in vss_result {
        vss_scheme_vec.push(vss_scheme);
        secret_shares_vec.push(secret_shares); // cannot unzip
        index_vec.push(index);
    }

    let party_shares = (0..n)
        .map(|i| {
            (0..n)
                .map(|j| {
                    let vec_j = &secret_shares_vec[j];
                    vec_j[i]
                })
                .collect::<Vec<FE>>()
        })
        .collect::<Vec<Vec<FE>>>();

    let mut shared_keys_vec = Vec::new();
    let mut dlog_proof_vec = Vec::new();
    for (i, key) in party_keys_vec.iter().enumerate() {
        let (shared_keys, dlog_proof) = key
            .phase2_verify_vss_construct_keypair_prove_dlog(
                &parames,
                &y_vec,
                &party_shares[i],
                &vss_scheme_vec,
                &(index_vec[i] + 1),
            )
            .expect("");
        shared_keys_vec.push(shared_keys);
        dlog_proof_vec.push(dlog_proof);
    }

    let vk_vec = (0..n).map(|i| dlog_proof_vec[i].pk).collect::<Vec<GE2>>();

    //all parties run:
    Keys::verify_dlog_proofs(&parames, &dlog_proof_vec).expect("");

    //test
    let xi_vec = (0..=t)
        .map(|i| shared_keys_vec[i].sk_i)
        .collect::<Vec<FE>>();
    let x = vss_scheme_vec[0]
        .clone()
        .reconstruct(&index_vec[0..=t], &xi_vec);
    let sum_u_i = party_keys_vec.iter().fold(FE::zero(), |acc, x| acc + x.u_i);
    assert_eq!(x, sum_u_i);

    (shared_keys_vec, vk_vec)
}

pub fn sign(
    message: &[u8],
    t: usize,
    n: usize,
    s: &[usize],
    keygen: Option<(Vec<SharedKeys>, Vec<GE2>)>,
) -> BLSSignature {
    // run keygen
    let (shared_keys_vec, vk_vec) = keygen.unwrap_or_else(|| keygen_t_n_parties(t, n));

    let t_prime = s.len();
    //carry on signing with shared keys of indices from s
    let shared_keys_participating_parties = (0..t_prime as usize)
        .map(|i| shared_keys_vec[s[i]].clone())
        .collect::<Vec<SharedKeys>>();
    let vk_participating_parties = (0..t_prime as usize)
        .map(|i| vk_vec[s[i]].clone())
        .collect::<Vec<GE2>>();

    // each party performs a partial sign
    let (partial_sign_vec, H_x): (Vec<_>, Vec<_>) = shared_keys_participating_parties
        .iter()
        .map(|k| k.partial_sign(message))
        .unzip();

    // each party runs Combine and out output the signature
    let bls_sig_vec = shared_keys_participating_parties
        .iter()
        .map(|k| {
            k.combine(
                &vk_participating_parties[..],
                &partial_sign_vec[..],
                H_x[0],
                s,
            )
            .expect("")
        })
        .collect::<Vec<BLSSignature>>();

    // test all signatures are equal
    let first = bls_sig_vec[0];
    assert!(bls_sig_vec.iter().all(|&item| item == first));
    // test the signatures pass verification
    assert!(shared_keys_vec[0].verify(&bls_sig_vec[0], message));

    bls_sig_vec[0]
}

#[cfg(test)]
#[test]
fn another_bls_impl_validates_signature() {
    use std::io::Cursor;

    use bls_sigs_ref::BLSSigCore;
    use pairing_plus::bls12_381::{G2Affine, G1, G2};
    use pairing_plus::hash_to_field::ExpandMsgXmd;
    use pairing_plus::serdes::SerDes;

    // Run keygen
    let keygen = keygen_t_n_parties(1, 2);
    let public_key = keygen.0[0].vk.clone();
    let mut public_key_bytes = vec![];
    G2Affine::serialize(&public_key.get_element(), &mut public_key_bytes, true)
        .expect("serialize to vec should always succeed");

    // Sign message
    let message = b"KZen";
    let signature = sign(&message[..], 1, 2, &[0, 1], Some(keygen)).to_bytes(true);

    // Parse public key & signature
    let public_key =
        G2::deserialize(&mut Cursor::new(public_key_bytes), true).expect("deserialize public key");
    let signature =
        G1::deserialize(&mut Cursor::new(signature), true).expect("deserialize signature");

    // Verify signature
    let cs = &[1u8];
    let valid =
        BLSSigCore::<ExpandMsgXmd<sha2::Sha256>>::core_verify(public_key, signature, message, cs);
    assert!(valid);
}

#[cfg(test)]
#[test]
fn we_recognize_signatures_generated_by_ref_impl() {
    use bls_sigs_ref::BLSSigCore;
    use pairing_plus::bls12_381::G1;
    use pairing_plus::hash_to_field::ExpandMsgXmd;

    // Keygen
    let (secret_key, public_key) = <G1 as BLSSigCore<ExpandMsgXmd<sha2::Sha256>>>::keygen(b"123");

    // Sign message
    let message = b"KZen";
    let cs = &[1u8];
    let signature: G1 =
        BLSSigCore::<ExpandMsgXmd<sha2::Sha256>>::core_sign(secret_key, message, cs);

    // Verify signature
    let valid =
        BLSSigCore::<ExpandMsgXmd<sha2::Sha256>>::core_verify(public_key, signature, message, cs);
    assert!(valid);

    // Now check that our primitive `BLSSignature` also successfully verifies signature
    let public_key = GE2::from(public_key.into_affine());
    let sigma = GE1::from(signature.into_affine());
    let signature = BLSSignature { sigma };
    let valid = signature.verify(message, &public_key);
    assert!(valid);
}
