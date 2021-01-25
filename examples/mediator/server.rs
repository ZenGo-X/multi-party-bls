use std::collections::HashMap;
use std::ops;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use futures::future::FutureExt;
use futures::stream::{Stream, StreamExt};
use tokio::sync::{Notify, RwLock};
use tonic::{Request, Response, Status, Streaming};
use tracing::{error, trace};

use super::proto::{self, Msg};

#[derive(Default)]
pub struct Server {
    rooms: RwLock<HashMap<Vec<u8>, Arc<Room>>>,
    garbage: AtomicBool,
}

#[tonic::async_trait]
impl proto::mediator_server::Mediator for Arc<Server> {
    type JoinStream = Pin<Box<dyn Stream<Item = Result<Msg, Status>> + Send + Sync + 'static>>;

    async fn join(
        &self,
        req: Request<Streaming<Msg>>,
    ) -> Result<Response<Self::JoinStream>, Status> {
        let room_id = match req.metadata().get("room-id") {
            Some(id) => id.as_bytes(),
            None => return Err(Status::invalid_argument("room-id is not provided")),
        };
        let room = self.join_room(room_id).await;
        let party_idx = room.join_idx();

        let mut msgs = vec![];
        let mut next_msg_idx = 0;
        let mut stream = req.into_inner().fuse();

        let response_stream = async_stream::stream! {
            loop {
                let event: Event = futures::select! {
                    idx = room.recv(next_msg_idx, &mut msgs).fuse() => Event::ForwardMessagesToClient(idx),
                    msg = stream.next() => Event::ClientSentMessage(msg),
                };
                match event {
                    Event::ForwardMessagesToClient(idx) => {
                        trace!("Forwarding messages to the client...");
                        next_msg_idx = idx;
                        for payload in msgs.drain(..) {
                            yield Ok(Msg{ payload })
                        }
                    }
                    Event::ClientSentMessage(Some(Ok(msg))) => {
                        trace!("Received message from client...");
                        room.add_msg(msg.payload).await
                    }
                    Event::ClientSentMessage(Some(Err(err))) => {
                        error!(%err, "Read message sent by client");
                        yield Err(err);
                        break
                    }
                    Event::ClientSentMessage(None) => {
                        trace!("Client disconnected (received EOF)");
                        break
                    }
                }
            }
        };
        let response_stream = Box::pin(response_stream) as Self::JoinStream;
        let mut response = Response::new(response_stream);
        response
            .metadata_mut()
            .insert("party-idx", tonic::metadata::MetadataValue::from(party_idx));
        Ok(response)
    }
}

enum Event {
    ForwardMessagesToClient(usize),
    ClientSentMessage(Option<Result<Msg, Status>>),
}

impl Server {
    pub fn new() -> Self {
        Self::default()
    }

    fn trigger_garbage_collection(&self) {
        self.garbage.store(true, Ordering::SeqCst)
    }

    async fn collect_garbage(&self) {
        let mut rooms = self.rooms.write().await;
        rooms.retain(|_, room| room.is_empty());
    }

    async fn join_room(self: &Arc<Self>, room_id: &[u8]) -> JoinHandler {
        self.collect_garbage().await;

        // At first we optimistically check if room exists
        let room = {
            let rooms = self.rooms.read().await;
            match rooms.get(room_id) {
                Some(room) => room.clone(),
                None => {
                    // Optimistic check failed. Go pessimistically
                    drop(rooms);
                    let mut rooms = self.rooms.write().await;
                    rooms
                        .entry(room_id.to_vec())
                        .or_insert_with(|| Arc::new(Room::default()))
                        .clone()
                }
            }
        };
        JoinHandler {
            idx: room.issue_next_party_idx(),
            server: self.clone(),
            room,
        }
    }
}

struct JoinHandler {
    idx: u32,
    server: Arc<Server>,
    room: Arc<Room>,
}

impl Clone for JoinHandler {
    fn clone(&self) -> Self {
        self.room.party_connected();
        Self {
            idx: self.idx,
            server: self.server.clone(),
            room: self.room.clone(),
        }
    }
}

impl JoinHandler {
    pub fn join_idx(&self) -> u32 {
        self.idx
    }
}

impl ops::Deref for JoinHandler {
    type Target = Room;
    fn deref(&self) -> &Self::Target {
        &self.room
    }
}

impl ops::Drop for JoinHandler {
    fn drop(&mut self) {
        if self.party_disconnected() {
            self.server.trigger_garbage_collection()
        }
    }
}

#[derive(Default)]
struct Room {
    idx: AtomicU32,
    parties_count: AtomicU32,
    messages: RwLock<Vec<Vec<u8>>>,
    changed: Notify,
}

impl Room {
    fn issue_next_party_idx(&self) -> u32 {
        self.idx.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn party_connected(&self) {
        self.parties_count.fetch_add(1, Ordering::SeqCst);
    }

    fn party_disconnected(&self) -> bool {
        self.parties_count.fetch_sub(1, Ordering::SeqCst) == 0
    }

    fn is_empty(&self) -> bool {
        self.parties_count.load(Ordering::SeqCst) == 0
    }

    async fn add_msg(&self, msg: Vec<u8>) {
        let mut history = self.messages.write().await;
        history.push(msg);
        drop(history);
        self.changed.notify_waiters()
    }

    async fn recv(&self, msg_id: usize, buffer: &mut Vec<Vec<u8>>) -> usize {
        loop {
            let history = self.messages.read().await;
            if history.len() <= msg_id {
                let notified = self.changed.notified();
                drop(history);
                notified.await;
                continue;
            }
            buffer.extend_from_slice(&history[msg_id..]);
            let len = history.len();

            drop(history);
            break len;
        }
    }
}

struct DeferCancel(Arc<Notify>);

impl ops::Drop for DeferCancel {
    fn drop(&mut self) {
        self.0.notify_waiters()
    }
}

#[cfg(test)]
pub mod test {
    use std::str::FromStr;

    use futures::future::FutureExt;
    use futures::{channel::mpsc, future, stream};
    use tokio::{net, sync, time};
    use tokio_stream::wrappers;
    use tonic::metadata::MetadataValue;
    use tonic::{transport, Request};

    use super::*;

    #[tokio::test]
    async fn server_provides_unique_client_idx() {
        let _ = tracing_subscriber::fmt::try_init();
        let stand = Stand::new().await;

        for i in 1u32..=5 {
            let mut client = stand.connect_client().await;
            let response: tonic::Response<_> = client
                .join(join_room("testing-room", stream::pending()))
                .await
                .unwrap();
            assert_eq!(
                response.metadata().get("party-idx"),
                Some(&tonic::metadata::MetadataValue::from(i))
            )
        }
    }

    #[tokio::test]
    async fn server_concurrently_provides_unique_client_idx() {
        const CONCURRENT_CLIENTS: usize = 50;
        let _ = tracing_subscriber::fmt::try_init();
        let stand = Stand::new().await;

        let mut handles = vec![];
        let barrier = Arc::new(sync::Barrier::new(CONCURRENT_CLIENTS));
        for _ in 0..CONCURRENT_CLIENTS {
            let barrier = barrier.clone();
            let mut client = stand.connect_client().await;
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                let response: tonic::Response<_> = client
                    .join(join_room("testing-room", stream::pending()))
                    .await
                    .unwrap();
                response.metadata().get("party-idx").cloned()
            }));
        }

        let mut indexes = vec![];
        for handle in handles {
            match handle.await {
                Ok(Some(index)) => {
                    let index = index.to_str().unwrap();
                    indexes.push(u32::from_str(index).unwrap())
                }
                Ok(None) => panic!("server didn't sent client index"),
                Err(err) => panic!("green thread panicked: {}", err),
            }
        }
        indexes.sort();

        let mut expected_indexes: Vec<_> = (1..=(CONCURRENT_CLIENTS as u32)).collect();
        expected_indexes.sort();

        println!("Got indexes: {:?}", indexes);
        println!("Expected   : {:?}", expected_indexes);

        assert_eq!(indexes, expected_indexes)
    }

    #[tokio::test]
    async fn delivers_message_to_everyone() {
        let _ = tracing_subscriber::fmt::try_init();
        let stand = Stand::new().await;

        let mut party1 = stand.connect_client().await;
        let mut party2 = stand.connect_client().await;
        let mut party3 = stand.connect_client().await;

        let msg = Msg {
            payload: b"Broadcasted message".to_vec(),
        };

        let mut party1_join = party1
            .join(join_room("testing-room", stream::pending()))
            .await
            .unwrap()
            .into_inner();
        let mut party2_join = party2
            .join(join_room("testing-room", stream::pending()))
            .await
            .unwrap()
            .into_inner();
        let mut party3_join = party3
            .join(join_room(
                "testing-room",
                stream::once(future::ready(msg.clone())).chain(stream::pending()),
            ))
            .await
            .unwrap()
            .into_inner();

        tracing::info!("Every party joint, start receiving");

        assert_eq!(party1_join.message().await.unwrap(), Some(msg.clone()));
        assert_eq!(party2_join.message().await.unwrap(), Some(msg.clone()));
        assert_eq!(party3_join.message().await.unwrap(), Some(msg.clone()));
    }

    #[tokio::test]
    async fn lately_joint_party_receives_all_messages() {
        let _ = tracing_subscriber::fmt::try_init();
        let stand = Stand::new().await;

        let mut party1 = stand.connect_client().await;
        let mut party2 = stand.connect_client().await;

        let (party1_outcoming, party1_rx) = mpsc::unbounded();
        let (party2_outcoming, party2_rx) = mpsc::unbounded();

        let mut party1_incoming = party1
            .join(join_room("testing-room", party1_rx))
            .await
            .unwrap()
            .into_inner();
        let mut party2_incoming = party2
            .join(join_room("testing-room", party2_rx))
            .await
            .unwrap()
            .into_inner();

        let msg1 = Msg {
            payload: b"msg1".to_vec(),
        };
        let msg2 = Msg {
            payload: b"msg2".to_vec(),
        };

        party1_outcoming.unbounded_send(msg1.clone()).unwrap();
        assert_eq!(party1_incoming.message().await.unwrap(), Some(msg1.clone()));
        assert_eq!(party2_incoming.message().await.unwrap(), Some(msg1.clone()));

        party2_outcoming.unbounded_send(msg2.clone()).unwrap();
        assert_eq!(party1_incoming.message().await.unwrap(), Some(msg2.clone()));
        assert_eq!(party2_incoming.message().await.unwrap(), Some(msg2.clone()));

        let mut party3 = stand.connect_client().await;
        let (party3_outcoming, party3_rx) = mpsc::unbounded();
        let mut party3_incoming = party3
            .join(join_room("testing-room", party3_rx))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(party3_incoming.message().await.unwrap(), Some(msg1.clone()));
        assert_eq!(party3_incoming.message().await.unwrap(), Some(msg2.clone()));

        let msg3 = Msg {
            payload: b"msg3".to_vec(),
        };

        party3_outcoming.unbounded_send(msg3.clone()).unwrap();
        assert_eq!(party1_incoming.message().await.unwrap(), Some(msg3.clone()));
        assert_eq!(party2_incoming.message().await.unwrap(), Some(msg3.clone()));
        assert_eq!(party3_incoming.message().await.unwrap(), Some(msg3.clone()));
    }

    #[tokio::test]
    async fn messages_from_different_rooms_dont_mess_with_each_other() {
        let _ = tracing_subscriber::fmt::try_init();
        let stand = Stand::new().await;

        let mut party1 = stand.connect_client().await;
        let mut party2 = stand.connect_client().await;

        let (party1_outcoming, party1_rx) = mpsc::unbounded();
        let (party2_outcoming, party2_rx) = mpsc::unbounded();

        let mut party1_incoming = party1
            .join(join_room("testing-room-1", party1_rx))
            .await
            .unwrap()
            .into_inner();
        let mut party2_incoming = party2
            .join(join_room("testing-room-2", party2_rx))
            .await
            .unwrap()
            .into_inner();

        let msg1 = Msg {
            payload: b"msg1".to_vec(),
        };
        let msg2 = Msg {
            payload: b"msg2".to_vec(),
        };

        party1_outcoming.unbounded_send(msg1.clone()).unwrap();
        party2_outcoming.unbounded_send(msg2.clone()).unwrap();

        assert_eq!(party1_incoming.message().await.unwrap(), Some(msg1.clone()));
        assert_eq!(party2_incoming.message().await.unwrap(), Some(msg2.clone()));

        futures::select! {
            _ = party1_incoming.message().fuse() => panic!("party1 received message"),
            _ = party2_incoming.message().fuse() => panic!("party2 received message"),
            _ = time::sleep(time::Duration::from_millis(100)).fuse() => println!("no more messages"),
        };
    }

    #[tokio::test]
    async fn history_cleans_after_all_parties_are_disconnected() {
        let _ = tracing_subscriber::fmt::try_init();
        let stand = Stand::new().await;

        let mut party1 = stand.connect_client().await;
        let mut party2 = stand.connect_client().await;

        let (party1_outcoming, party1_rx) = mpsc::unbounded();
        let (party2_outcoming, party2_rx) = mpsc::unbounded();

        let mut party1_incoming = party1
            .join(join_room("testing-room", party1_rx))
            .await
            .unwrap()
            .into_inner();
        let mut party2_incoming = party2
            .join(join_room("testing-room", party2_rx))
            .await
            .unwrap()
            .into_inner();

        let msg1 = Msg {
            payload: b"msg1".to_vec(),
        };
        let msg2 = Msg {
            payload: b"msg2".to_vec(),
        };

        party1_outcoming.unbounded_send(msg1.clone()).unwrap();
        assert_eq!(party1_incoming.message().await.unwrap(), Some(msg1.clone()));
        assert_eq!(party2_incoming.message().await.unwrap(), Some(msg1.clone()));

        party2_outcoming.unbounded_send(msg2.clone()).unwrap();
        assert_eq!(party1_incoming.message().await.unwrap(), Some(msg2.clone()));
        assert_eq!(party2_incoming.message().await.unwrap(), Some(msg2.clone()));

        drop((party1_outcoming, party2_outcoming));

        let mut party3 = stand.connect_client().await;
        let (party3_outcoming, party3_rx) = mpsc::unbounded();
        let mut party3_incoming = party3
            .join(join_room("testing-room", party3_rx))
            .await
            .unwrap()
            .into_inner();

        let msg3 = Msg {
            payload: b"msg3".to_vec(),
        };

        party3_outcoming.unbounded_send(msg3.clone()).unwrap();
        assert_eq!(party3_incoming.message().await.unwrap(), Some(msg3.clone()));

        futures::select! {
            _ = party3_incoming.message().fuse() => panic!("party3 received message"),
            _ = time::sleep(time::Duration::from_millis(100)).fuse() => println!("no more messages"),
        };
    }

    pub struct Stand {
        server_handler: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
        server_addr: std::net::SocketAddr,
    }

    impl Stand {
        pub async fn new() -> Self {
            let incoming_clients = net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let server_addr = incoming_clients.local_addr().unwrap();
            let mediator = proto::mediator_server::MediatorServer::new(Arc::new(Server::new()));
            let serve = transport::Server::builder()
                .add_service(mediator)
                .serve_with_incoming(wrappers::TcpListenerStream::new(incoming_clients));
            let server_handler = tokio::spawn(serve);
            Self {
                server_handler,
                server_addr,
            }
        }

        pub fn server_addr(&self) -> std::net::SocketAddr {
            self.server_addr.clone()
        }

        pub async fn connect_client(
            &self,
        ) -> proto::mediator_client::MediatorClient<tonic::transport::Channel> {
            let channel =
                tonic::transport::Endpoint::from_shared(format!("http://{}", self.server_addr))
                    .unwrap()
                    .connect()
                    .await
                    .unwrap();
            proto::mediator_client::MediatorClient::new(channel)
        }
    }

    impl Drop for Stand {
        fn drop(&mut self) {
            self.server_handler.abort()
        }
    }

    fn join_room<S>(room_id: &str, outcoming: S) -> Request<S> {
        let mut request = Request::new(outcoming);
        request
            .metadata_mut()
            .insert("room-id", MetadataValue::from_str(room_id).unwrap());
        request
    }
}
