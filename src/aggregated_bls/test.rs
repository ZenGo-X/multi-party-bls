use crate::aggregated_bls::party_i::{Keys, APK};
use crate::basic_bls::BLSSignature;
use curv::elliptic::curves::bls12_381::g2::GE as GE2;

// test 3 out of 3
#[test]
fn agg_sig_test_3() {
    let p1_keys = Keys::new(0);
    let p2_keys = Keys::new(1);
    let p3_keys = Keys::new(2);

    // each party broadcasts its public key pk_i
    let pk_vec = vec![p1_keys.pk_i, p2_keys.pk_i, p3_keys.pk_i];

    // each party computes APK
    let apk = Keys::aggregate(&pk_vec);

    // each party signs locally :
    let message = vec![10, 11, 12, 13];
    let s1 = p1_keys.local_sign(&message, &pk_vec);
    let s2 = p2_keys.local_sign(&message, &pk_vec);
    let s3 = p3_keys.local_sign(&message, &pk_vec);

    // a dealer combines all local signatures
    let sig_vec = vec![s1, s2, s3];
    let bls_sig = Keys::combine_local_signatures(&sig_vec);

    // anyone can verify
    assert_eq!(bls_sig.verify(&message, &apk), true);
    assert_ne!(bls_sig.verify(&message, &p1_keys.pk_i), true);
    assert_ne!(bls_sig.verify(&[10, 11, 12], &apk), true);
}

// test batch 3 out of 3 for 3 messages
#[test]
pub fn test_agg_sig_3_batch_3() {
    let msg_vec = vec![[1].as_ref(), [2].as_ref(), [3].as_ref()];
    let bad_m_v = vec![[4].as_ref(), [5].as_ref(), [6].as_ref()];
    agg_sig_test_n_batch_m(3, &msg_vec, &bad_m_v);
}

#[test]
pub fn test_agg_sig_3_batch_5() {
    let msg_vec = vec![
        [1].as_ref(),
        [2].as_ref(),
        [3].as_ref(),
        [4].as_ref(),
        [5].as_ref(),
    ];
    let bad_m_v = vec![
        [6].as_ref(),
        [7].as_ref(),
        [8].as_ref(),
        [9].as_ref(),
        [10].as_ref(),
    ];
    agg_sig_test_n_batch_m(3, &msg_vec, &bad_m_v);
}

#[test]
pub fn test_agg_sig_3_batch_2() {
    let msg_vec = vec![
        [1].as_ref(),
        [2].as_ref(),
    ];
    let bad_m_v = vec![
        [6].as_ref(),
        [7].as_ref(),
    ];
    agg_sig_test_n_batch_m(3, &msg_vec, &bad_m_v);
}

// test batch n out of n for m messages
pub fn agg_sig_test_n_batch_m(n: usize, msg_vec: &[&[u8]], bad_m_v: &[&[u8]]) {
    assert_eq!(msg_vec.len(), bad_m_v.len());
    let m = msg_vec.len();
    let (mkey_vec, pk_vec, apk_vec) = keygen_batch(n, m);

    let bls_sig = sign_batch(n, &mkey_vec, &pk_vec, msg_vec);

    // test batch aggregation to verify as correct
    assert_eq!(
        Keys::aggregate_verify(&apk_vec, msg_vec, &bls_sig),
        true
    );

    // test verification to fail a bad entry in apk_vec
    let (_, _, bad_a_v) = keygen_batch(n, m);
    assert_ne!(
        Keys::aggregate_verify(&bad_a_v, msg_vec, &bls_sig),
        true
    );

    // test verification to fail a bad entry in msg_vec
    assert_ne!(
        Keys::aggregate_verify(&apk_vec, bad_m_v, &bls_sig),
        true
    );

    // test verification to fail a bad bls signature
    let (bad_k_v, bad_p_v, _) = keygen_batch(n, m);
    let bad_b_s = sign_batch(n, &bad_k_v, &bad_p_v, msg_vec);
    assert_ne!(
        Keys::aggregate_verify(&apk_vec, msg_vec, &bad_b_s),
        true
    );
}

fn keygen(n_parties: usize) -> (Vec<Keys>, Vec<GE2>, APK) {
    let keys_vec: Vec<Keys> = (0..n_parties).map(|i| Keys::new(i)).collect();
    let pk_vec: Vec<GE2> = keys_vec.iter().map(|x| x.pk_i).collect();
    let apk = Keys::aggregate(&pk_vec);
    (keys_vec, pk_vec, apk)
}

fn keygen_batch(n_parties: usize, m_batches: usize) -> (Vec<Vec<Keys>>, Vec<Vec<GE2>>, Vec<APK>) {
    let keygen_vec_batch: Vec<_> = (0..m_batches).map(|_| keygen(n_parties)).collect();
    let keys_vec_batch = keygen_vec_batch.iter().map(|x| x.0.clone()).collect();
    let pk_vec_batch = keygen_vec_batch.iter().map(|x| x.1.clone()).collect();
    let apk_vec_batch = keygen_vec_batch.iter().map(|x| x.2.clone()).collect();
    (keys_vec_batch, pk_vec_batch, apk_vec_batch)
}

fn sign_batch(
    n_parties: usize,
    key_vec: &Vec<Vec<Keys>>,
    pk_vec: &Vec<Vec<GE2>>,
    msg_vec: &[&[u8]],
) -> BLSSignature {
    let sig_vec: Vec<Vec<_>> = (0..msg_vec.len())
        .map(|i| {
            (0..n_parties)
                .map(|j| key_vec[i][j].local_sign(msg_vec[i], &pk_vec[i]))
                .collect()
        })
        .collect();
    let bls_sig_vec: Vec<_> = (0..msg_vec.len())
        .map(|i| Keys::combine_local_signatures(&sig_vec[i]))
        .collect();
    Keys::batch_aggregate_bls(&bls_sig_vec)
}
