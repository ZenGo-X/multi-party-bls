use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use futures::stream::FusedStream;
use futures::{channel::mpsc, future, Sink, SinkExt, Stream};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;
use tonic::metadata::MetadataValue;
use tonic::{transport, Request, Response};

use round_based::Msg;

use super::proto;
use super::proto::mediator_client::MediatorClient;

pub struct Client {
    channel: transport::Channel,
}

impl From<transport::Channel> for Client {
    fn from(channel: transport::Channel) -> Self {
        Self { channel }
    }
}

impl Client {
    pub async fn connect(addr: SocketAddr) -> Result<Self> {
        let channel = transport::Endpoint::from_shared(format!("http://{}", addr))
            .context("invalid endpoint uri which was built from socket addr")?
            .connect()
            .await
            .context("connect to server")?;
        Ok(Client { channel })
    }

    pub async fn join<T>(
        self,
        room_id: &str,
    ) -> Result<(
        u16,
        impl Stream<Item = std::result::Result<Msg<T>, RecvError>> + FusedStream,
        impl Sink<Msg<T>, Error = SendError>,
    )>
    where
        T: Serialize + DeserializeOwned + Send + 'static,
    {
        let mut client = MediatorClient::new(self.channel);

        let (mut incoming_tx, incoming_rx) = mpsc::channel(10);
        let (outcoming_tx, outcoming_rx) = mpsc::channel(10);

        let room_id = MetadataValue::from_str(room_id).context("malformed room_id")?;
        let mut request = Request::new(outcoming_rx);
        request.metadata_mut().insert("room-id", room_id);
        let response: Response<_> = client.join(request).await.context("join room")?;
        let client_idx = response
            .metadata()
            .get("party-idx")
            .ok_or(anyhow!("server didn't provide client idx"))?
            .to_str()
            .context("invalid client idx")?;
        let client_idx =
            u16::from_str(client_idx).context("cannot convert client idx to integer")?;
        let mut server_messages = response.into_inner();

        tokio::spawn(async move {
            loop {
                match server_messages.message().await {
                    Ok(Some(msg)) => {
                        let m = Self::deserialize::<T>(&msg.payload)
                            .context("deserialize incoming message")
                            .map_err(RecvError);
                        if let Ok(m) = m.as_ref() {
                            if m.sender == client_idx
                                || m.receiver.is_some() && m.receiver != Some(client_idx)
                            {
                                continue;
                            }
                        }
                        if let Err(_) = incoming_tx.send(m).await {
                            break;
                        }
                    }
                    Err(e) => {
                        let e = Err(e).context("recv msg").map_err(RecvError);
                        if let Err(_) = incoming_tx.send(e).await {
                            break;
                        }
                    }
                    Ok(None) => break,
                }
            }
        });

        Ok((
            client_idx,
            incoming_rx,
            outcoming_tx.with(|x| future::ready(Self::serialize(x).map_err(SendError))),
        ))
    }

    fn serialize<T: Serialize>(msg: Msg<T>) -> Result<proto::Msg> {
        let payload = serde_json::to_vec(&msg).context("serialize msg")?;
        Ok(proto::Msg { payload })
    }

    fn deserialize<T: DeserializeOwned>(buf: &[u8]) -> Result<Msg<T>> {
        serde_json::from_slice(buf).context("deserialize msg")
    }
}

/// Wraps [anyhow::Error] and implements [std::error::Error] trait
#[derive(Error, Debug)]
#[error(transparent)]
pub struct RecvError(anyhow::Error);

/// Wraps [anyhow::Error] and implements [std::error::Error] trait
#[derive(Error, Debug)]
#[error(transparent)]
pub struct SendError(anyhow::Error);

impl From<mpsc::SendError> for SendError {
    fn from(err: mpsc::SendError) -> SendError {
        SendError(anyhow::Error::new(err))
    }
}

#[cfg(test)]
mod test {
    use futures::{FutureExt, StreamExt};
    use tokio::time;

    use super::*;

    #[tokio::test]
    async fn broadcast_works() {
        let _ = tracing_subscriber::fmt::try_init();
        let stand = Stand::new().await;

        let party1 = stand.connect_client().await;
        let party2 = stand.connect_client().await;
        let party3 = stand.connect_client().await;

        let (party1_idx, mut party1_incoming, mut party1_outcoming) =
            party1.join("testing-room").await.unwrap();
        let (party2_idx, mut party2_incoming, mut party2_outcoming) =
            party2.join("testing-room").await.unwrap();
        let (party3_idx, mut party3_incoming, _party3_outcoming) =
            party3.join("testing-room").await.unwrap();

        assert_eq!(party1_idx, 1);
        assert_eq!(party2_idx, 2);
        assert_eq!(party3_idx, 3);

        let msg1 = Msg {
            sender: party1_idx,
            receiver: None,
            body: "Hey bodies".to_string(),
        };
        let msg2 = Msg {
            sender: party2_idx,
            receiver: None,
            body: "Hello friends".to_string(),
        };

        party1_outcoming.send(msg1.clone()).await.unwrap();
        assert_eq!(
            Some(msg1.clone()),
            party2_incoming.next().await.transpose().unwrap()
        );
        assert_eq!(
            Some(msg1),
            party3_incoming.next().await.transpose().unwrap()
        );
        futures::select! {
            _ = party1_incoming.next() => panic!("party1 received its own message"),
            _ = time::sleep(time::Duration::from_millis(100)).fuse() => (),
        };

        party2_outcoming.send(msg2.clone()).await.unwrap();
        assert_eq!(
            Some(msg2.clone()),
            party1_incoming.next().await.transpose().unwrap()
        );
        assert_eq!(
            Some(msg2),
            party3_incoming.next().await.transpose().unwrap()
        );
        futures::select! {
            _ = party2_incoming.next() => panic!("party2 received its own message"),
            _ = time::sleep(time::Duration::from_millis(100)).fuse() => (),
        };
    }

    #[tokio::test]
    async fn p2p_works() {
        let _ = tracing_subscriber::fmt::try_init();
        let stand = Stand::new().await;

        let party1 = stand.connect_client().await;
        let party2 = stand.connect_client().await;

        let (party1_idx, mut party1_incoming, mut party1_outcoming) =
            party1.join("testing-room").await.unwrap();
        let (party2_idx, mut party2_incoming, mut party2_outcoming) =
            party2.join("testing-room").await.unwrap();

        assert_eq!(party1_idx, 1);
        assert_eq!(party2_idx, 2);

        let msg1 = Msg {
            sender: party1_idx,
            receiver: Some(party2_idx),
            body: "Hey you".to_string(),
        };
        let msg2 = Msg {
            sender: party2_idx,
            receiver: Some(party1_idx),
            body: "Hi".to_string(),
        };

        party1_outcoming.send(msg1.clone()).await.unwrap();
        assert_eq!(
            Some(msg1),
            party2_incoming.next().await.transpose().unwrap()
        );
        futures::select! {
            _ = party1_incoming.next() => panic!("party1 received its own message"),
            _ = time::sleep(time::Duration::from_millis(100)).fuse() => (),
        };

        party2_outcoming.send(msg2.clone()).await.unwrap();
        assert_eq!(
            Some(msg2),
            party1_incoming.next().await.transpose().unwrap()
        );
        futures::select! {
            _ = party2_incoming.next() => panic!("party2 received its own message"),
            _ = time::sleep(time::Duration::from_millis(100)).fuse() => (),
        };
    }

    struct Stand(crate::mediator::server::test::Stand);

    impl Stand {
        pub async fn new() -> Self {
            Stand(crate::mediator::server::test::Stand::new().await)
        }

        pub async fn connect_client(&self) -> Client {
            Client::connect(self.0.server_addr()).await.unwrap()
        }
    }
}
