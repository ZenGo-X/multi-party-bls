use std::net;
use std::path::PathBuf;

use structopt::StructOpt;

#[derive(StructOpt, Debug)]
/// Demo CLI
pub struct App {
    /// Address of mediator server
    ///
    /// Parties use mediator server to speak with each other
    #[structopt(long = "addr", default_value = "127.0.0.1:8333")]
    pub mediator_addr: net::SocketAddr,
    /// How many threads will be used for async environment
    #[structopt(short, long)]
    pub threads: Option<usize>,
    #[structopt(subcommand)]
    pub command: Cmd,
}

#[derive(StructOpt, Debug)]
pub enum Cmd {
    MediatorServer(MediatorCmd),
    Keygen(KeygenArgs),
    Sign(SignArgs),
    Verify(VerifyArgs),
}

#[derive(StructOpt, Debug)]
/// Distributed key generation
pub struct KeygenArgs {
    /// Threshold value `t`.
    ///
    /// `t`+1 parties will be required to perform signing
    #[structopt(short = "t", long)]
    pub threshold: u16,
    /// Number of parties involved in keygen
    #[structopt(short = "n", long)]
    pub parties: u16,
    /// Where to save resulting local party key
    ///
    /// If file already exist, it will be overwritten
    #[structopt(short, long)]
    pub output: PathBuf,

    /// Room identifier
    ///
    /// Every performing protocol (keygen/sign) must have dedicated room. You don't need to
    /// specify room id as long as you don't execute several protocols simultaneously.
    #[structopt(long, default_value = "default-room")]
    pub room_id: String,
}

#[derive(StructOpt, Debug)]
/// Threshold signing
pub struct SignArgs {
    /// Local secret key path
    #[structopt(long)]
    pub key: PathBuf,

    /// Number of parties involved in signing
    #[structopt(short = "n", long)]
    pub parties: u16,

    /// Message to sign
    #[structopt(long, parse(from_str))]
    pub digits: Bytes,

    /// Room identifier
    ///
    /// Every performing protocol (keygen/sign) must have dedicated room. You don't need to
    /// specify room id as long as you don't execute several protocols simultaneously.
    #[structopt(long, default_value = "default-room")]
    pub room_id: String,
}

type Bytes = Vec<u8>;

#[derive(StructOpt, Debug)]
/// Locally verifies that message matches signature
pub struct VerifyArgs {
    /// Public key which was used to sign message
    #[structopt(long)]
    pub public_key: String,
    /// Signature
    #[structopt(long)]
    pub signature: String,
    /// Being verified message
    #[structopt(long, parse(from_str))]
    pub digits: Bytes,
}

#[derive(StructOpt, Debug)]
/// Manages mediator server (parties' communication layer)
pub enum MediatorCmd {
    /// Starts mediator server
    Run,
}
