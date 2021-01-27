//! ## How to use it
//! To execute any protocol (keygen/signing) in [tokio] async environment, you need to define
//! message delivery logic and construct stream of incoming messages and sink for outcoming
//! messages. Then you can execute protocol using [AsyncProtocol](round_based::AsyncProtocol)
//! (see below).
//!
//! [tokio]: https://tokio.rs
//!
//! Messages delivery should meet security assumptions:
//! * Any P2P message must be encrypted so no one can read it except recipient
//! * Broadcast messages must be signed, so no one can forge message sender
//!
//! ### Keygen
//! ```no_run
//! use round_based::{Msg, AsyncProtocol};
//! use bls::threshold_bls::state_machine::keygen::{Keygen, ProtocolMessage};
//!
//! # use std::convert::Infallible;
//! # use anyhow::{Result, Error};
//! # use futures::stream::{self, Stream, FusedStream};
//! # use futures::sink::{self, Sink, SinkExt};
//! # use thiserror::Error;
//! #
//! # #[derive(Error, Debug)]
//! # enum SendErr {}
//! # impl From<Infallible> for SendErr { fn from(_: Infallible) -> Self { unimplemented!() } }
//! # #[derive(Error, Debug)]
//! # enum RecvErr {}
//! #
//! async fn connect() -> Result<(
//!     // Party's unique index in range [1;parties_count]
//!     u16,
//!     // Incoming messages
//!     impl Stream<Item=Result<Msg<ProtocolMessage>, RecvErr>> + FusedStream + Unpin,
//!     // Outcoming messages
//!     impl Sink<Msg<ProtocolMessage>, Error=SendErr> + Unpin,                        
//! )> {
//!     // ...
//!     # Ok((0, stream::pending(), sink::drain().with(|x| futures::future::ok(x))))
//! }
//!
//! # async fn keygen(t: u16, n: u16) -> Result<()> {
//! let (i, incoming, outcoming) = connect().await?;
//! // n - number of parties involved in keygen, t - threshold value, i - party's index
//! let keygen = Keygen::new(i, t, n)?;
//! let local_key = AsyncProtocol::new(keygen, incoming, outcoming)
//!     .run().await?;
//! println!("Public key: {:?}", local_key.public_key());
//! # Ok(())
//! # }
//! ```
//!
//! ### Sign
//! ```no_run
//! use round_based::{Msg, AsyncProtocol};
//! # use bls::threshold_bls::state_machine::keygen::LocalKey;
//! use bls::threshold_bls::state_machine::sign::{Sign, ProtocolMessage};
//!
//! # use std::convert::Infallible;
//! # use anyhow::{Result, Error};
//! # use futures::stream::{self, Stream, FusedStream};
//! # use futures::sink::{self, Sink, SinkExt};
//! # use thiserror::Error;
//! #
//! # #[derive(Error, Debug)]
//! # enum SendErr {}
//! # impl From<Infallible> for SendErr { fn from(_: Infallible) -> Self { unimplemented!() } }
//! # #[derive(Error, Debug)]
//! # enum RecvErr {}
//! #
//! async fn connect() -> Result<(
//!     // Party's unique index in range [1;parties_count]
//!     u16,
//!     // Incoming messages
//!     impl Stream<Item=Result<Msg<ProtocolMessage>, RecvErr>> + FusedStream + Unpin,
//!     // Outcoming messages
//!     impl Sink<Msg<ProtocolMessage>, Error=SendErr> + Unpin,                        
//! )> {
//!     // ...
//!     # Ok((0, stream::pending(), sink::drain().with(|x| futures::future::ok(x))))
//! }
//!
//! # async fn sign(local_key: LocalKey, message: Vec<u8>, t: u16, n: u16) -> Result<()> {
//! let (i, incoming, outcoming) = connect().await?;
//! // message - bytes to sign, n - number of parties involved in signing,
//! // local_key - local secret key obtained by this party at keygen
//! let signing = Sign::new(message, i, n, local_key)?;
//! let (_, sig) = AsyncProtocol::new(signing, incoming, outcoming)
//!     .run().await?;
//! println!("Signature: {:?}", sig);
//! # Ok(())
//! # }
//! ```

pub mod aggregated_bls;
pub mod basic_bls;
pub mod threshold_bls;
/// BLS verification should follow the BLS standard:
/// [https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04]
/// Therefore, it should be possible to use this library ONLY in applications that follow
/// the standard as well. e.g. Algorand [https://github.com/algorand/bls_sigs_ref]

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    KeyGenMisMatchedVectors,
    KeyGenBadCommitment,
    KeyGenInvalidShare,
    KeyGenDlogProofError,
    PartialSignatureVerificationError,
    SigningMisMatchedVectors,
}
