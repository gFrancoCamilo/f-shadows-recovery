// Copyright(C) Facebook, Inc. and its affiliates.
#![allow(warnings)]
use crate::error::NetworkError;
use bytes::Bytes;
use futures::sink::SinkExt as _;
use futures::stream::StreamExt as _;
use log::{info, warn};
use rand::prelude::SliceRandom as _;
use rand::rngs::SmallRng;
use rand::SeedableRng as _;
use std::collections::HashMap;
use std::net::{SocketAddr};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use rand::Rng;
use std::{thread, time};

#[cfg(test)]
#[path = "tests/delayed_sender_tests.rs"]
pub mod delayed_sender_tests;


/// We keep alive one TCP connection per peer, each connection is handled by a separate task (called `Connection`).
/// We communicate with our 'connections' through a dedicated channel kept by the HashMap called `connections`.
pub struct DelayedSender {
    /// A map holding the channels to our connections.
    connections: HashMap<SocketAddr, Sender<Bytes>>,
    /// Small RNG just used to shuffle nodes and randomize connections (not crypto related).
    rng: SmallRng,
    pub firewall: HashMap<u64, Vec<SocketAddr>>,
    //pub firewall: Vec<SocketAddr>,
    //pub new_firewall: Vec<SocketAddr>,
    pub allow_communications_at_round: u64,
    pub network_delay: u64,
    pub dns: HashMap<SocketAddr, SocketAddr>,
}

impl std::default::Default for DelayedSender {
    fn default() -> Self {
        Self::new(HashMap::new(), 20000, 10, HashMap::new())
    }
}

impl DelayedSender {
    pub fn new(firewall: HashMap<u64,Vec<SocketAddr>>, round: u64, network_delay: u64, dns: HashMap<SocketAddr, SocketAddr>) -> Self {
        Self {
            connections: HashMap::new(),
            rng: SmallRng::from_entropy(),
            firewall: firewall,
            //new_firewall: new_firewall,
            allow_communications_at_round: round,
            network_delay: network_delay,
            dns:dns
        }
    }

    /// Helper function to spawn a new connection.
    fn spawn_connection(address: SocketAddr) -> Sender<Bytes> {
        let (tx, rx) = channel(1_000);
        Connection::spawn(address, rx);
        tx
    }

    /// Try (best-effort) to send a message to a specific address.
    /// This is useful to answer sync requests.
    pub async fn send(&mut self, address: SocketAddr, data: Bytes, current_round: u64) {

        // We compute a random number that will be used to simulate transmission delay
        //let delay = rand::thread_rng().gen_range(0,self.network_delay);
        //thread::sleep(time::Duration::from_millis(delay));
        let virtual_address = self.dns[&address];

        //if !self.firewall.get(&(current_round/self.allow_communications_at_round)).unwrap_or(&self.firewall[&((self.firewall.len()-1) as u64)]).contains(&address){
        if !self.firewall.get(&((self.firewall.len()-1) as u64)).unwrap().contains(&virtual_address){
            info!("Sending message to address {:?}", address);
            // Try to re-use an existing connection if possible.
            if let Some(tx) = self.connections.get(&address) {
                //info!("Timestamp going into send is {:?}. Sending to {:?} in round {}", time::SystemTime::now().duration_since(time::SystemTime::UNIX_EPOCH), address, current_round);
                if tx.send(data.clone()).await.is_ok() {
                    return;
                }
            }
        
            // Otherwise make a new connection.
            let tx = Self::spawn_connection(address);
            //info!("Timestamp going into send is {:?}. Sending to {:?} in round {}", time::SystemTime::now().duration_since(time::SystemTime::UNIX_EPOCH), address, current_round);
            if tx.send(data).await.is_ok() {
                self.connections.insert(address, tx);
            }
        }
    }

    /// Try (best-effort) to broadcast the message to all specified addresses.
    pub async fn broadcast(&mut self, addresses: Vec<SocketAddr>, data: Bytes, current_round: u64) {
        for address in addresses {
            self.send(address, data.clone(), current_round).await;
        }
    }

    /// Pick a few addresses at random (specified by `nodes`) and try (best-effort) to send the
    /// message only to them. This is useful to pick nodes with whom to sync.
    pub async fn lucky_broadcast(
        &mut self,
        mut addresses: Vec<SocketAddr>,
        data: Bytes,
        nodes: usize,
        current_round: u64,
    ) {
        addresses.shuffle(&mut self.rng);
        addresses.truncate(nodes);
        self.broadcast(addresses, data, current_round).await
    }
}

/// A connection is responsible to establish and keep alive (if possible) a connection with a single peer.
struct Connection {
    /// The destination address.
    address: SocketAddr,
    /// Channel from which the connection receives its commands.
    receiver: Receiver<Bytes>,
}

impl Connection {
    fn spawn(address: SocketAddr, receiver: Receiver<Bytes>) {
        tokio::spawn(async move {
            Self { address, receiver }.run().await;
        });
    }

    /// Main loop trying to connect to the peer and transmit messages.
    async fn run(&mut self) {
        // Try to connect to the peer.
        let (mut writer, mut reader) = match TcpStream::connect(self.address).await {
            Ok(stream) => Framed::new(stream, LengthDelimitedCodec::new()).split(),
            Err(e) => {
                warn!(
                    "{}",
                    NetworkError::FailedToConnect(self.address, /* retry */ 0, e)
                );
                return;
            }
        };
        info!("Outgoing connection established with {}", self.address);

        // Transmit messages once we have established a connection.
        loop {
            // Check if there are any new messages to send or if we get an ACK for messages we already sent.
            tokio::select! {
                Some(data) = self.receiver.recv() => {
                    if let Err(e) = writer.send(data).await {
                        warn!("{}", NetworkError::FailedToSendMessage(self.address, e));
                        return;
                    }
                },
                response = reader.next() => {
                    match response {
                        Some(Ok(_)) => {
                            // Sink the reply.
                        },
                        _ => {
                            // Something has gone wrong (either the channel dropped or we failed to read from it).
                            warn!("{}", NetworkError::FailedToReceiveAck(self.address));
                            return;
                        }
                    }
                },
            }
        }
    }
}
