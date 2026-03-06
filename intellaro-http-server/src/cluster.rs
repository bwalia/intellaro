//! Clustering and High Availability module.
//!
//! Provides multi-node configuration synchronization, leader election,
//! health monitoring, and cluster-wide state replication.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::config::ClusterConfig;

/// The state of a peer node in the cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerState {
    /// Unique node identifier.
    pub node_id: String,

    /// Address of the peer.
    pub address: String,

    /// Last heartbeat timestamp (Unix epoch seconds).
    pub last_heartbeat: u64,

    /// Whether this peer is considered alive.
    pub alive: bool,

    /// Configuration version this peer is running.
    pub config_version: u64,
}

/// Cluster-internal message types exchanged between nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClusterMessage {
    /// Periodic heartbeat from a node.
    Heartbeat {
        node_id: String,
        config_version: u64,
    },

    /// Configuration sync request.
    ConfigSyncRequest {
        from_node: String,
        config_version: u64,
    },

    /// Configuration sync response containing the full config payload.
    ConfigSyncResponse {
        from_node: String,
        config_version: u64,
        config_payload: String,
    },

    /// Cache invalidation broadcast.
    CacheInvalidation {
        from_node: String,
        cache_key: String,
    },

    /// Full cache purge broadcast.
    CachePurge {
        from_node: String,
    },
}

/// The cluster manager coordinates multi-node operations.
pub struct ClusterManager {
    /// This node's unique identifier.
    node_id: String,

    /// Known peers and their states.
    peers: Arc<DashMap<String, PeerState>>,

    /// Current configuration version counter.
    config_version: Arc<RwLock<u64>>,

    /// Cluster communication port.
    port: u16,

    /// Peer addresses for initial discovery.
    seed_peers: Vec<String>,
}

impl ClusterManager {
    /// Create a new cluster manager from configuration.
    pub fn new(config: &ClusterConfig) -> Self {
        let node_id = if config.node_id.is_empty() {
            Uuid::new_v4().to_string()
        } else {
            config.node_id.clone()
        };

        info!(
            node_id = %node_id,
            peers = config.peers.len(),
            port = config.port,
            "Cluster manager initialized"
        );

        Self {
            node_id,
            peers: Arc::new(DashMap::new()),
            config_version: Arc::new(RwLock::new(0)),
            port: config.port,
            seed_peers: config.peers.clone(),
        }
    }

    /// Start the cluster manager background tasks.
    ///
    /// This spawns:
    /// - A UDP listener for receiving cluster messages.
    /// - A heartbeat sender that broadcasts to all peers.
    /// - A peer health monitor that marks unresponsive peers as dead.
    pub async fn start(
        self: Arc<Self>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bind_addr: SocketAddr = format!("0.0.0.0:{}", self.port).parse()?;
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);

        info!(address = %bind_addr, "Cluster UDP socket bound");

        // Initialize seed peers.
        for peer_addr in &self.seed_peers {
            let peer_id = peer_addr.clone();
            self.peers.insert(
                peer_id.clone(),
                PeerState {
                    node_id: peer_id,
                    address: peer_addr.clone(),
                    last_heartbeat: current_timestamp(),
                    alive: true,
                    config_version: 0,
                },
            );
        }

        metrics::gauge!("cluster_peers").set(self.peers.len() as f64);

        // Spawn the message receiver.
        let receiver_self = Arc::clone(&self);
        let recv_socket = Arc::clone(&socket);
        tokio::spawn(async move {
            receiver_self.receive_loop(recv_socket).await;
        });

        // Spawn the heartbeat sender.
        let heartbeat_self = Arc::clone(&self);
        let send_socket = Arc::clone(&socket);
        tokio::spawn(async move {
            heartbeat_self.heartbeat_loop(send_socket).await;
        });

        // Spawn the peer health monitor.
        let monitor_self = Arc::clone(&self);
        tokio::spawn(async move {
            monitor_self.health_monitor_loop().await;
        });

        Ok(())
    }

    /// Return a snapshot of all known peers.
    pub fn get_peers(&self) -> Vec<PeerState> {
        self.peers.iter().map(|entry| entry.value().clone()).collect()
    }

    /// Get the current configuration version.
    pub async fn get_config_version(&self) -> u64 {
        *self.config_version.read().await
    }

    /// Increment the configuration version (called after a config change).
    pub async fn bump_config_version(&self) -> u64 {
        let mut version = self.config_version.write().await;
        *version += 1;
        *version
    }

    /// Broadcast a cache invalidation to all peers.
    pub async fn broadcast_cache_invalidation(
        &self,
        socket: &UdpSocket,
        cache_key: &str,
    ) {
        let message = ClusterMessage::CacheInvalidation {
            from_node: self.node_id.clone(),
            cache_key: cache_key.to_string(),
        };

        self.broadcast(socket, &message).await;
    }

    /// Broadcast a full cache purge to all peers.
    pub async fn broadcast_cache_purge(&self, socket: &UdpSocket) {
        let message = ClusterMessage::CachePurge {
            from_node: self.node_id.clone(),
        };

        self.broadcast(socket, &message).await;
    }

    // ── Internal loops ──────────────────────────────────────────────

    /// Continuously receive and process cluster messages.
    async fn receive_loop(&self, socket: Arc<UdpSocket>) {
        let mut buf = vec![0u8; 65535];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    let data = &buf[..len];
                    match serde_json::from_slice::<ClusterMessage>(data) {
                        Ok(message) => {
                            self.handle_message(message, src).await;
                        }
                        Err(err) => {
                            warn!(%src, %err, "Invalid cluster message");
                        }
                    }
                }
                Err(err) => {
                    error!(%err, "Cluster socket recv error");
                }
            }
        }
    }

    /// Periodically send heartbeats to all known peers.
    async fn heartbeat_loop(&self, socket: Arc<UdpSocket>) {
        let interval = Duration::from_secs(5);

        loop {
            tokio::time::sleep(interval).await;

            let config_version = *self.config_version.read().await;
            let message = ClusterMessage::Heartbeat {
                node_id: self.node_id.clone(),
                config_version,
            };

            self.broadcast(&socket, &message).await;
        }
    }

    /// Periodically check peer health and mark unresponsive peers as dead.
    async fn health_monitor_loop(&self) {
        let interval = Duration::from_secs(10);
        let timeout_secs = 30u64;

        loop {
            tokio::time::sleep(interval).await;

            let now = current_timestamp();

            for mut entry in self.peers.iter_mut() {
                let peer = entry.value_mut();
                let elapsed = now.saturating_sub(peer.last_heartbeat);

                if elapsed > timeout_secs && peer.alive {
                    warn!(
                        node_id = %peer.node_id,
                        elapsed_secs = elapsed,
                        "Peer marked as dead"
                    );
                    peer.alive = false;
                } else if elapsed <= timeout_secs && !peer.alive {
                    info!(node_id = %peer.node_id, "Peer recovered");
                    peer.alive = true;
                }
            }

            let alive_count = self.peers.iter().filter(|e| e.value().alive).count();
            metrics::gauge!("cluster_peers").set(alive_count as f64);
        }
    }

    /// Handle a received cluster message.
    async fn handle_message(&self, message: ClusterMessage, src: SocketAddr) {
        match message {
            ClusterMessage::Heartbeat {
                node_id,
                config_version,
            } => {
                debug!(from = %node_id, config_version, "Heartbeat received");

                self.peers
                    .entry(node_id.clone())
                    .and_modify(|peer| {
                        peer.last_heartbeat = current_timestamp();
                        peer.alive = true;
                        peer.config_version = config_version;
                    })
                    .or_insert_with(|| PeerState {
                        node_id,
                        address: src.to_string(),
                        last_heartbeat: current_timestamp(),
                        alive: true,
                        config_version,
                    });
            }

            ClusterMessage::CacheInvalidation {
                from_node,
                cache_key,
            } => {
                debug!(from = %from_node, key = %cache_key, "Cache invalidation received");
                // TODO: Delegate to CacheLayer::invalidate(cache_key)
            }

            ClusterMessage::CachePurge { from_node } => {
                debug!(from = %from_node, "Cache purge received");
                // TODO: Delegate to CacheLayer::purge()
            }

            ClusterMessage::ConfigSyncRequest {
                from_node,
                config_version,
            } => {
                debug!(
                    from = %from_node,
                    requested_version = config_version,
                    "Config sync request received"
                );
                // TODO: Send ConfigSyncResponse with current config
            }

            ClusterMessage::ConfigSyncResponse {
                from_node,
                config_version,
                config_payload,
            } => {
                debug!(
                    from = %from_node,
                    version = config_version,
                    payload_len = config_payload.len(),
                    "Config sync response received"
                );
                // TODO: Apply config if version is newer
            }
        }
    }

    /// Broadcast a message to all known peers.
    async fn broadcast(&self, socket: &UdpSocket, message: &ClusterMessage) {
        let payload = match serde_json::to_vec(message) {
            Ok(data) => data,
            Err(err) => {
                error!(%err, "Failed to serialize cluster message");
                return;
            }
        };

        for entry in self.peers.iter() {
            let peer = entry.value();
            if let Ok(addr) = peer.address.parse::<SocketAddr>() {
                if let Err(err) = socket.send_to(&payload, addr).await {
                    warn!(
                        peer = %peer.node_id,
                        %err,
                        "Failed to send cluster message"
                    );
                }
            }
        }
    }
}

/// Get the current Unix epoch timestamp in seconds.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
