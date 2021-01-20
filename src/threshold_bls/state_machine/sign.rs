use std::fmt;
use std::mem::replace;
use std::time::Duration;

use curv::elliptic::curves::bls12_381::g1::GE as GE1;
use round_based::containers::*;
use round_based::{Msg, StateMachine};

use crate::basic_bls::BLSSignature;
use crate::threshold_bls::party_i;
use crate::threshold_bls::state_machine::keygen::LocalKey;

mod rounds;
pub use rounds::{Error, M};
use rounds::{Result, Round0, Round1, R};

pub struct Sign {
    round: R,

    msgs1: Option<Store<BroadcastMsgs<(u16, party_i::PartialSignature)>>>,

    msgs_queue: Vec<Msg<M>>,

    party_i: u16,
    party_n: u16,
}

impl Sign {
    /// Constructs a party of signing protocol
    ///
    /// Takes party index `i` (in range `[1; n]`), number of parties involved in
    /// signing `n`, and local key obtained in keygen. Party index identifies this party
    /// in the protocol, so it must be guaranteed to be unique.
    ///
    /// Returns error if:
    /// * `n` is less than `threshold+1`, returns [Error::TooFewParties]
    /// * `n` more than number of parties holding a key (who took a part in keygen),
    ///   returns [Error::TooManyParties]
    /// * `i` is not in range `[1; n]`, returns [Error::InvalidPartyIndex]
    pub fn new(message: Vec<u8>, i: u16, n: u16, local_key: LocalKey) -> Result<Self> {
        if n < local_key.t + 1 {
            return Err(Error::TooFewParties);
        }
        if n > local_key.n {
            return Err(Error::TooManyParties);
        }
        if i == 0 || i > n {
            return Err(Error::InvalidPartyIndex);
        }
        let mut state = Self {
            round: R::Round0(Round0 {
                key: local_key,
                message,
                i,
                n,
            }),

            msgs1: Some(Round1::expects_messages(i, n)),

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
                next_state = round.proceed(msgs).map(R::Final)?;
                true
            }
            s @ R::Round1(_) => {
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

impl StateMachine for Sign {
    type MessageBody = M;
    type Err = Error;
    type Output = (GE1, BLSSignature);

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
        }
    }

    fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
        &mut self.msgs_queue
    }

    fn wants_to_proceed(&self) -> bool {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);

        match &self.round {
            R::Round0(_) => true,
            R::Round1(_) => !store1_wants_more,
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
            R::Final(_) | R::Gone => 2,
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

impl fmt::Debug for Sign {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let current_round = match &self.round {
            R::Round0(_) => "0",
            R::Round1(_) => "1",
            R::Final(_) => "[Final]",
            R::Gone => "[Gone]",
        };
        let msgs1 = match self.msgs1.as_ref() {
            Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
            None => "[None]".into(),
        };
        write!(
            f,
            "{{MPCRandom at round={} msgs1={} queue=[len={}]}}",
            current_round,
            msgs1,
            self.msgs_queue.len()
        )
    }
}

#[cfg(test)]
mod test {
    use round_based::dev::Simulation;

    use super::*;
    use crate::threshold_bls::state_machine::Keygen;

    fn simulate_sign(msg: &[u8], s: &[u16], t: u16, n: u16) {
        // Keygen
        let mut keygen_simulation = Simulation::new();
        for i in 1..=n {
            keygen_simulation.add_party(Keygen::new(i, t, n).unwrap());
        }
        let parties_keys = keygen_simulation.run().unwrap();

        // Sign
        let mut sign_simulation = Simulation::new();
        sign_simulation.enable_benchmarks(true);

        let parties_keys: Vec<_> = s
            .iter()
            .map(|&i| parties_keys[usize::from(i) - 1].clone())
            .collect();
        let n = s.len() as u16;
        for (i, key) in (1..).zip(parties_keys.clone()) {
            sign_simulation.add_party(Sign::new(msg.into(), i, n, key).unwrap());
        }

        let (_, sigs): (Vec<_>, Vec<_>) = sign_simulation.run().unwrap().into_iter().unzip();

        // test all signatures are equal
        let first = sigs[0];
        assert!(sigs.iter().all(|&item| item == first));
        // test the signatures pass verification
        assert!(parties_keys[0].shared_keys.verify(&sigs[0], msg));

        println!("Benchmarks:");
        println!("{:#?}", sign_simulation.benchmark_results().unwrap());
    }

    #[test]
    fn simulate_sign_t1_n2() {
        let msg = b"~~ MESSAGE ~~";
        simulate_sign(&msg[..], &[1, 2], 1, 2);
    }

    #[test]
    fn simulate_sign_t1_n3() {
        let msg = b"~~ MESSAGE ~~";
        simulate_sign(&msg[..], &[1, 2], 1, 3);
    }

    #[test]
    fn simulate_sign_t2_n3() {
        let msg = b"~~ MESSAGE ~~";
        simulate_sign(&msg[..], &[1, 2, 3], 2, 3);
    }
}
