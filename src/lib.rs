pub mod basic_bls;
pub mod threshold_bls;

/// BLS verification should follow the BLS standard:
/// [https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04]
/// Therefore, it should be possible to use this library ONLY in applications that follow
/// the standard as well. i.e. Algorand blockchain.

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    KeyGenMisMatchedVectors,
    KeyGenBadCommitment,
    KeyGenInvalidShare,
    KeyGenDlogProofError,
    PartialSignatureVerificationError,
    SigningMisMatchedVectors,
}
