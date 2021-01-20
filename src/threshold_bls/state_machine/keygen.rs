use std::fmt;
use std::mem::replace;
use std::time::Duration;

use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::bls12_381::g2::FE as FE2;
use curv::elliptic::curves::bls12_381::g2::GE as GE2;
use round_based::containers::*;
use round_based::{Msg, StateMachine};

use crate::threshold_bls::party_i;

mod rounds;
pub use rounds::{Error, LocalKey, M};
use rounds::{Result, Round0, Round1, Round2, Round3, Round4, R};

pub struct Keygen {
    round: R,

    msgs1: Option<Store<BroadcastMsgs<party_i::KeyGenComm>>>,
    msgs2: Option<Store<BroadcastMsgs<party_i::KeyGenDecom>>>,
    msgs3: Option<Store<P2PMsgs<(VerifiableSS<GE2>, FE2)>>>,
    msgs4: Option<Store<BroadcastMsgs<DLogProof<GE2>>>>,

    msgs_queue: Vec<Msg<M>>,

    party_i: u16,
    party_n: u16,
}

impl Keygen {
    /// Constructs a party of keygen protocol
    ///
    /// Takes party index `i` (in range `[1; n]`), threshold value `t`, and total number of
    /// parties `n`. Party index identifies this party in the protocol, so it must be guaranteed
    /// to be unique.
    ///
    /// Returns error if:
    /// * `n` is less than 2, returns [Error::TooFewParties]
    /// * `t` is not in range `[1; n-1]`, returns [Error::InvalidThreshold]
    /// * `i` is not in range `[1; n]`, returns [Error::InvalidPartyIndex]
    pub fn new(i: u16, t: u16, n: u16) -> Result<Self> {
        if n < 2 {
            return Err(Error::TooFewParties);
        }
        if t == 0 || t >= n {
            return Err(Error::InvalidThreshold);
        }
        if i == 0 || i > n {
            return Err(Error::InvalidPartyIndex);
        }
        let mut state = Self {
            round: R::Round0(Round0 { party_i: i, t, n }),

            msgs1: Some(Round1::expects_messages(i, n)),
            msgs2: Some(Round2::expects_messages(i, n)),
            msgs3: Some(Round3::expects_messages(i, n)),
            msgs4: Some(Round4::expects_messages(i, n)),

            msgs_queue: vec![],

            party_i: i,
            party_n: n,
        };

        state.proceed_round(false)?;
        Ok(state)
    }

    /// Proceeds round state if it received enough messages and if it's cheap to compute or
    /// `may_block == true`
    fn proceed_round(&mut self, may_block: bool) -> Result<()> {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store2_wants_more = self.msgs2.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store3_wants_more = self.msgs3.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store4_wants_more = self.msgs4.as_ref().map(|s| s.wants_more()).unwrap_or(false);

        let next_state: R;
        let try_again: bool = match replace(&mut self.round, R::Gone) {
            R::Round0(round) if !round.is_expensive() || may_block => {
                next_state = round.proceed(&mut self.msgs_queue).map(R::Round1)?;
                true
            }
            s @ R::Round0(_) => {
                next_state = s;
                false
            }
            R::Round1(round) if !store1_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs1.take().expect("store gone before round complete");
                let msgs = store.finish().map_err(Error::RetrieveRoundMessages)?;
                next_state = round.proceed(msgs, &mut self.msgs_queue).map(R::Round2)?;
                true
            }
            s @ R::Round1(_) => {
                next_state = s;
                false
            }
            R::Round2(round) if !store2_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs2.take().expect("store gone before round complete");
                let msgs = store.finish().map_err(Error::RetrieveRoundMessages)?;
                next_state = round.proceed(msgs, &mut self.msgs_queue).map(R::Round3)?;
                true
            }
            s @ R::Round2(_) => {
                next_state = s;
                false
            }
            R::Round3(round) if !store3_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs3.take().expect("store gone before round complete");
                let msgs = store.finish().map_err(Error::RetrieveRoundMessages)?;
                next_state = round.proceed(msgs, &mut self.msgs_queue).map(R::Round4)?;
                true
            }
            s @ R::Round3(_) => {
                next_state = s;
                false
            }
            R::Round4(round) if !store4_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs4.take().expect("store gone before round complete");
                let msgs = store.finish().map_err(Error::RetrieveRoundMessages)?;
                next_state = round.proceed(msgs).map(R::Final)?;
                true
            }
            s @ R::Round4(_) => {
                next_state = s;
                false
            }
            s @ R::Final(_) | s @ R::Gone => {
                next_state = s;
                false
            }
        };

        self.round = next_state;
        if try_again {
            self.proceed_round(may_block)
        } else {
            Ok(())
        }
    }
}

impl StateMachine for Keygen {
    type MessageBody = M;
    type Err = Error;
    type Output = LocalKey;

    fn handle_incoming(&mut self, msg: Msg<Self::MessageBody>) -> Result<()> {
        let current_round = self.current_round();

        match msg.body {
            M::Round1(m) => {
                let store = self
                    .msgs1
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 1,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
                self.proceed_round(false)
            }
            M::Round2(m) => {
                let store = self
                    .msgs2
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
                self.proceed_round(false)
            }
            M::Round3(m) => {
                let store = self
                    .msgs3
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 3,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
                self.proceed_round(false)
            }
            M::Round4(m) => {
                let store = self
                    .msgs4
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 4,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
                self.proceed_round(false)
            }
        }
    }

    fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
        &mut self.msgs_queue
    }

    fn wants_to_proceed(&self) -> bool {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store2_wants_more = self.msgs2.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store3_wants_more = self.msgs3.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store4_wants_more = self.msgs4.as_ref().map(|s| s.wants_more()).unwrap_or(false);

        match &self.round {
            R::Round0(_) => true,
            R::Round1(_) => !store1_wants_more,
            R::Round2(_) => !store2_wants_more,
            R::Round3(_) => !store3_wants_more,
            R::Round4(_) => !store4_wants_more,
            R::Final(_) | R::Gone => false,
        }
    }

    fn proceed(&mut self) -> Result<()> {
        self.proceed_round(true)
    }

    fn round_timeout(&self) -> Option<Duration> {
        None
    }

    fn round_timeout_reached(&mut self) -> Self::Err {
        panic!("no timeout was set")
    }

    fn is_finished(&self) -> bool {
        matches!(self.round, R::Final(_))
    }

    fn pick_output(&mut self) -> Option<Result<Self::Output>> {
        match self.round {
            R::Final(_) => (),
            R::Gone => return Some(Err(Error::DoublePickResult)),
            _ => return None,
        }

        match replace(&mut self.round, R::Gone) {
            R::Final(result) => Some(Ok(result)),
            _ => unreachable!("guaranteed by match expression above"),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            R::Round0(_) => 0,
            R::Round1(_) => 1,
            R::Round2(_) => 2,
            R::Round3(_) => 3,
            R::Round4(_) => 4,
            R::Final(_) | R::Gone => 5,
        }
    }

    fn total_rounds(&self) -> Option<u16> {
        Some(4)
    }

    fn party_ind(&self) -> u16 {
        self.party_i
    }

    fn parties(&self) -> u16 {
        self.party_n
    }
}

impl fmt::Debug for Keygen {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let current_round = match &self.round {
            R::Round0(_) => "0",
            R::Round1(_) => "1",
            R::Round2(_) => "2",
            R::Round3(_) => "3",
            R::Round4(_) => "4",
            R::Final(_) => "[Final]",
            R::Gone => "[Gone]",
        };
        let msgs1 = match self.msgs1.as_ref() {
            Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
            None => "[None]".into(),
        };
        let msgs2 = match self.msgs2.as_ref() {
            Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
            None => "[None]".into(),
        };
        let msgs3 = match self.msgs3.as_ref() {
            Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
            None => "[None]".into(),
        };
        let msgs4 = match self.msgs4.as_ref() {
            Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
            None => "[None]".into(),
        };
        write!(
            f,
            "{{MPCRandom at round={} msgs1={} msgs2={} msgs3={} msgs4={} queue=[len={}]}}",
            current_round,
            msgs1,
            msgs2,
            msgs3,
            msgs4,
            self.msgs_queue.len()
        )
    }
}

#[cfg(test)]
mod test {
    use round_based::dev::Simulation;

    use super::*;

    fn simulate_keygen(t: u16, n: u16) -> Vec<LocalKey> {
        let mut simulation = Simulation::new();
        simulation.enable_benchmarks(true);

        for i in 1..=n {
            simulation.add_party(Keygen::new(i, t, n).unwrap());
        }

        let keys = simulation.run().unwrap();

        println!("Benchmark results:");
        println!("{:#?}", simulation.benchmark_results().unwrap());

        keys
    }

    #[test]
    fn simulate_keygen_t1_n2() {
        simulate_keygen(1, 2);
    }

    #[test]
    fn simulate_keygen_t1_n3() {
        simulate_keygen(1, 3);
    }

    #[test]
    fn simulate_keygen_t2_n3() {
        simulate_keygen(2, 3);
    }
}
