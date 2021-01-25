mod client;
mod server;

pub use client::Client;
pub use server::Server;

pub mod proto {
    tonic::include_proto!("internal.mediator");
}
