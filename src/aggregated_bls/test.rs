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
