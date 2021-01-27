use std::net::SocketAddr;
use std::process::exit;

use anyhow::{anyhow, bail, Context, Result};
use structopt::StructOpt;
use tokio::runtime;
use tracing::{error, info};

mod cli_args;
mod mediator;

use cli_args::{App, Cmd, KeygenArgs, MediatorCmd, SignArgs, VerifyArgs};

fn main() {
    tracing_subscriber::fmt::init();
    let app: App = App::from_args();

    // Build async runtime
    let mut runtime = runtime::Builder::new_multi_thread();

    runtime.enable_all();

    if let Some(t) = app.threads {
        runtime.worker_threads(t);
    }

    let runtime = match runtime.build() {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to build async runtime: {}", e);
            exit(1)
        }
    };

    // Execute requested command
    let result = runtime.block_on(async move {
        match app.command {
            Cmd::MediatorServer(MediatorCmd::Run) => mediator_server_run(app.mediator_addr).await,
            Cmd::Keygen(args) => keygen(app.mediator_addr, args).await,
            Cmd::Sign(args) => sign(app.mediator_addr, args).await,
            Cmd::Verify(args) => verify(args),
        }
    });

    if let Err(e) = result {
        error!("{}", e);
        exit(1);
    }
}

async fn mediator_server_run(addr: SocketAddr) -> Result<()> {
    use std::sync::Arc;

    use tokio::net;
    use tokio_stream::wrappers;
    use tonic::transport;

    let incoming_clients = net::TcpListener::bind(addr).await.unwrap();
    let mediator =
        mediator::proto::mediator_server::MediatorServer::new(Arc::new(mediator::Server::new()));
    info!("Starting mediator server");
    transport::Server::builder()
        .add_service(mediator)
        .serve_with_incoming(wrappers::TcpListenerStream::new(incoming_clients))
        .await
        .context("running mediator-server")
}

async fn keygen(
    mediator_addr: SocketAddr,
    KeygenArgs {
        threshold: t,
        parties: n,
        output: output_path,
        room_id,
    }: KeygenArgs,
) -> Result<()> {
    let client = mediator::Client::connect(mediator_addr).await?;
    let (i, incoming, outcoming) = client.join(&room_id).await?;
    if i > n {
        bail!(
            "too many party joint to perform keygen (at least {} whereas only {} expected)",
            i - 1,
            n
        )
    }

    let keygen = bls::threshold_bls::state_machine::keygen::Keygen::new(i, t, n)
        .context("construct keygen initial state")?;
    info!("Start keygen");
    let output = round_based::AsyncProtocol::new(keygen, incoming, outcoming)
        .run()
        .await
        .context("keygen execution error")?;
    info!("Keygen successfully finished!");

    let local_key = serde_json::to_vec(&output).context("serialize local secret key")?;
    if let Some(parent_dir) = output_path.parent() {
        tokio::fs::create_dir_all(parent_dir)
            .await
            .context("create dir")?;
    }
    tokio::fs::write(&output_path, local_key)
        .await
        .context("save local secret key to file")?;
    info!("Local secret key saved to {:?}", output_path);

    let public_key = curv::elliptic::curves::traits::ECPoint::pk_to_key_slice(&output.public_key());
    println!("Public key: {}", hex::encode(public_key));

    Ok(())
}

async fn sign(
    mediator_addr: SocketAddr,
    SignArgs {
        key: secret_key,
        parties: n,
        digits: digest,
        room_id,
    }: SignArgs,
) -> Result<()> {
    let secret = tokio::fs::read(secret_key)
        .await
        .context("read file with local secret key")?;
    let secret = serde_json::from_slice(&secret).context("deserialize local secret key")?;

    let client = mediator::Client::connect(mediator_addr).await?;
    let (i, incoming, outcoming) = client.join(&room_id).await?;
    if i > n {
        bail!(
            "too many party joint to perform keygen (at least {} whereas only {} expected)",
            i - 1,
            n
        )
    }

    let signing = bls::threshold_bls::state_machine::sign::Sign::new(digest, i, n, secret)
        .context("construct signing initial state")?;

    info!("Start signing");
    let (_, sig) = round_based::AsyncProtocol::new(signing, incoming, outcoming)
        .run()
        .await
        .context("sign execution error")?;
    info!("Signing successfully finished!");

    let public_key = curv::elliptic::curves::traits::ECPoint::pk_to_key_slice(&sig.sigma);
    println!("Signature: {}", hex::encode(public_key));
    Ok(())
}

fn verify(
    VerifyArgs {
        public_key,
        signature,
        digits: digest,
    }: VerifyArgs,
) -> Result<()> {
    use curv::elliptic::curves::bls12_381::{g1::GE as GE1, g2::GE as GE2};
    use curv::elliptic::curves::traits::ECPoint;

    use bls::basic_bls::BLSSignature;

    let public_key =
        hex::decode(public_key).context("public key is not valid hex encoded string")?;
    let signature =
        hex::decode(signature).context("signature key is not valid hex encoded string")?;

    let signature = GE1::from_bytes(&signature)
        .map_err(|e| anyhow!("signature is not valid g1 point: {:?}", e))?;
    let public_key = GE2::from_bytes(&public_key)
        .map_err(|e| anyhow!("public key is not valid g2 point: {:?}", e))?;

    let valid = BLSSignature { sigma: signature }.verify(&digest, &public_key);
    if valid {
        println!("Signature is valid");
    } else {
        bail!("Signature is not valid");
    }

    Ok(())
}
