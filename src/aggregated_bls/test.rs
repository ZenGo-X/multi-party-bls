use crate::aggregated_bls::party_i::Keys;

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
fn agg_sig_test_3_batch_3() {
    let key_vec: Vec<Vec<_>> = (0..3)
        .map(|_| (0..3).map(|j| Keys::new(j)).collect())
        .collect();

    let pk_vec: Vec<Vec<_>> = (0..3)
        .map(|i| (0..3).map(|j| key_vec[i][j].pk_i).collect())
        .collect();

    let apk_vec: Vec<_> = (0..3).map(|i| Keys::aggregate(&pk_vec[i])).collect();

    let msg_vec = vec![[1].as_ref(), [2].as_ref(), [3].as_ref()];

    let sig_vec: Vec<Vec<_>> = (0..3)
        .map(|i| {
            (0..3)
                .map(|j| key_vec[i][j].local_sign(msg_vec[i], &pk_vec[i]))
                .collect()
        })
        .collect();

    let bls_sig_vec: Vec<_> = (0..3)
        .map(|i| Keys::combine_local_signatures(&sig_vec[i]))
        .collect();

    let bls_sig_agg = Keys::aggregate_bls(&bls_sig_vec);

    assert_eq!(
        Keys::aggregate_verify(&apk_vec, &msg_vec, &bls_sig_agg),
        true
    );
    assert_eq!(
        Keys::aggregate_verify(&[apk_vec[0]; 3], &msg_vec, &bls_sig_agg),
        false
    );

    let bad_msg_vec = vec![[4].as_ref(), [5].as_ref(), [6].as_ref()];
    assert_eq!(
        Keys::aggregate_verify(&apk_vec, &bad_msg_vec, &bls_sig_agg),
        false
    );
    assert_eq!(
        Keys::aggregate_verify(&apk_vec, &msg_vec, &Keys::aggregate_bls(&[bls_sig_vec[0]])),
        false
    );

    let rep_msg_vec = vec![[1].as_ref(), [1].as_ref(), [1].as_ref()];
    let rep_sig_vec: Vec<Vec<_>> = (0..3)
        .map(|i| {
            (0..3)
                .map(|j| key_vec[i][j].local_sign(&rep_msg_vec[i], &pk_vec[i]))
                .collect()
        })
        .collect();
    let rep_bls_sig_vec: Vec<_> = (0..3)
        .map(|i| Keys::combine_local_signatures(&rep_sig_vec[i]))
        .collect();
    let rep_bls_sig_agg = Keys::aggregate_bls(&rep_bls_sig_vec);
    assert_eq!(
        Keys::aggregate_verify(&apk_vec, &rep_msg_vec, &rep_bls_sig_agg),
        false
    );
}
