//! E2EE SFU Example
//!
//! A modified version of the chat example that uses RTP mode for opaque
//! payload forwarding. The SFU never inspects media payloads — it forwards
//! encrypted RTP packets based on header metadata (SSRC, MID, RID) only.
//!
//! Clients use Insertable Streams to encrypt/decrypt media frames end-to-end.
//! The SFU serves the E2EE client UI from the `e2ee-client/` directory.
//!
//! Usage:
//!   cargo run --example e2ee_chat --no-default-features --features "wincrypto,examples"
//!
//! Then open https://<ip>:3000 in Chrome.

#[macro_use]
extern crate tracing;

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::sync::{Arc, Weak};
use std::thread;
use std::time::{Duration, Instant};

use rouille::Server;
use rouille::{Request, Response};
use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::{ChannelData, ChannelId};
use str0m::crypto::from_feature_flags;
use str0m::media::{Direction, KeyframeRequest, Mid, Rid};
use str0m::media::{KeyframeRequestKind, MediaKind};
use str0m::net::Protocol;
use str0m::net::Receive;
use str0m::rtp::RtpPacket;
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc, RtcError};

mod util;

fn init_log() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("e2ee_chat=info,str0m=info,dimpl=info"));

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(env_filter)
        .init();
}

// Inline the E2EE client HTML — reads from the e2ee-client directory at compile time.
// For development, you can also serve files from disk instead.
const E2EE_INDEX_HTML: &str = include_str!("../../e2ee-client/index.html");
const E2EE_MAIN_JS: &str = include_str!("../../e2ee-client/main.js");
const E2EE_CRYPTO_JS: &str = include_str!("../../e2ee-client/crypto.js");
const E2EE_WORKER_JS: &str = include_str!("../../e2ee-client/e2ee-worker.js");
const E2EE_CONTRACT_JS: &str = include_str!("../../e2ee-client/e2ee-contract.js");
const E2EE_KEY_EXCHANGE_JS: &str = include_str!("../../e2ee-client/key-exchange.js");
const E2EE_REKEY_JS: &str = include_str!("../../e2ee-client/rekey.js");

pub fn main() {
    init_log();

    from_feature_flags().install_process_default();

    let certificate = include_bytes!("cer.pem").to_vec();
    let private_key = include_bytes!("key.pem").to_vec();

    let host_addr = util::select_host_address();

    let (tx, rx) = mpsc::sync_channel(1);

    let socket = UdpSocket::bind(format!("{host_addr}:0")).expect("binding a random UDP port");
    let addr = socket.local_addr().expect("a local socket address");
    info!("Bound UDP port: {}", addr);

    thread::spawn(move || run(socket, rx));

    let server = Server::new_ssl(
        "0.0.0.0:3000",
        move |request| web_request(request, addr, tx.clone()),
        certificate,
        private_key,
    )
    .expect("starting the web server");

    let port = server.server_addr().port();
    info!("E2EE SFU ready — connect browser to https://{:?}:{:?}", addr.ip(), port);

    server.run();
}

fn web_request(request: &Request, addr: SocketAddr, tx: SyncSender<Rtc>) -> Response {
    // Serve the E2EE client files
    match (request.method(), request.url().as_str()) {
        ("GET", "/") | ("GET", "/index.html") => {
            return Response::from_data("text/html", E2EE_INDEX_HTML);
        }
        ("GET", "/main.js") => {
            return Response::from_data("application/javascript", E2EE_MAIN_JS);
        }
        ("GET", "/crypto.js") => {
            return Response::from_data("application/javascript", E2EE_CRYPTO_JS);
        }
        ("GET", "/e2ee-worker.js") => {
            return Response::from_data("application/javascript", E2EE_WORKER_JS);
        }
        ("GET", "/e2ee-contract.js") => {
            return Response::from_data("application/javascript", E2EE_CONTRACT_JS);
        }
        ("GET", "/key-exchange.js") => {
            return Response::from_data("application/javascript", E2EE_KEY_EXCHANGE_JS);
        }
        ("GET", "/rekey.js") => {
            return Response::from_data("application/javascript", E2EE_REKEY_JS);
        }
        _ => {}
    }

    if request.method() == "POST" && request.url().as_str() == "/start" {
        return handle_start(request, addr, tx);
    }

    Response::empty_404()
}

fn handle_start(request: &Request, addr: SocketAddr, tx: SyncSender<Rtc>) -> Response {
    let Some(mut data) = request.data() else {
        return Response::json(&serde_json::json!({"error": "no body"})).with_status_code(400);
    };

    let offer: SdpOffer = match serde_json::from_reader(&mut data) {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to parse SDP offer: {:?}", e);
            return Response::json(&serde_json::json!({"error": format!("bad offer: {e}")}))
                .with_status_code(400);
        }
    };

    let mut rtc = Rtc::builder()
        .set_rtp_mode(true)
        .build(Instant::now());

    let candidate = Candidate::host(addr, "udp").expect("a host candidate");
    rtc.add_local_candidate(candidate).unwrap();

    let answer = match rtc.sdp_api().accept_offer(offer) {
        Ok(answer) => answer,
        Err(e) => {
            error!("Failed to accept SDP offer: {:?}", e);
            return Response::json(&serde_json::json!({"error": format!("accept failed: {e}")}))
                .with_status_code(500);
        }
    };

    if let Err(e) = tx.send(rtc) {
        error!("Failed to send Rtc to run loop: {:?}", e);
        return Response::json(&serde_json::json!({"error": "server busy"}))
            .with_status_code(503);
    }

    let body = serde_json::to_vec(&answer).expect("answer to serialize");
    Response::from_data("application/json", body)
}

// ─── Main Run Loop ────────────────────────────────────────

fn run(socket: UdpSocket, rx: Receiver<Rtc>) -> Result<(), RtcError> {
    let mut clients: Vec<Client> = vec![];
    let mut to_propagate: VecDeque<Propagated> = VecDeque::new();
    let mut buf = vec![0; 2000];

    loop {
        clients.retain(|c| c.rtc.is_alive());

        if let Some(mut client) = spawn_new_client(&rx) {
            for track in clients.iter().flat_map(|c| c.tracks_in.iter()) {
                let weak = Arc::downgrade(&track.id);
                client.handle_track_open(weak);
            }
            clients.push(client);
        }

        let mut timeout = Instant::now() + Duration::from_millis(100);
        for client in clients.iter_mut() {
            let t = poll_until_timeout(client, &mut to_propagate, &socket);
            timeout = timeout.min(t);
        }

        if let Some(propagated) = to_propagate.pop_front() {
            propagate(&propagated, &mut clients);
            continue;
        }

        let duration = (timeout - Instant::now()).max(Duration::from_millis(1));
        socket
            .set_read_timeout(Some(duration))
            .expect("setting read timeout");

        if let Some(input) = read_socket_input(&socket, &mut buf) {
            if let Some(client) = clients.iter_mut().find(|c| c.accepts(&input)) {
                client.handle_input(input);
            }
        }

        let now = Instant::now();
        for client in &mut clients {
            client.handle_input(Input::Timeout(now));
        }
    }
}

fn propagate(propagated: &Propagated, clients: &mut [Client]) {
    match propagated {
        Propagated::TrackOpen(origin, weak) => {
            for client in clients.iter_mut() {
                if client.id == *origin {
                    continue;
                }
                client.handle_track_open(weak.clone());
            }
        }
        Propagated::RtpPacket(origin, mid, packet) => {
            for client in clients.iter_mut() {
                if client.id == *origin {
                    continue;
                }
                // Forward opaque RTP packet to all other clients
                client.handle_rtp_packet_out(*origin, *mid, packet);
            }
        }
        Propagated::KeyframeRequest(origin, req, mid_in) => {
            for client in clients.iter_mut() {
                if client.id != *origin {
                    continue;
                }
                client.handle_keyframe_request(req, *mid_in);
            }
        }
        Propagated::ChannelData(origin, data) => {
            // E2EE key exchange relay: forward DataChannel messages to all other clients
            for client in clients.iter_mut() {
                if client.id == *origin {
                    continue;
                }
                client.relay_channel_data(data);
            }
        }
        Propagated::Noop => {}
    }
}

fn spawn_new_client(rx: &Receiver<Rtc>) -> Option<Client> {
    match rx.try_recv() {
        Ok(rtc) => {
            let id = ClientId::new();
            info!("New E2EE client: {}", *id);
            Some(Client {
                id,
                rtc,
                pending: None,
                cid_sdp: None,
                cid_e2ee: None,
                tracks_in: Vec::new(),
                tracks_out: Vec::new(),
            })
        }
        Err(TryRecvError::Empty) => None,
        Err(TryRecvError::Disconnected) => panic!("Web server thread disconnected"),
    }
}

fn poll_until_timeout(
    client: &mut Client,
    to_propagate: &mut VecDeque<Propagated>,
    socket: &UdpSocket,
) -> Instant {
    loop {
        match client.rtc.poll_output() {
            Ok(output) => match output {
                Output::Timeout(t) => return t,
                Output::Transmit(t) => {
                    socket.send_to(&t.contents, t.destination).ok();
                }
                Output::Event(e) => {
                    let p = client.handle_event(e);
                    to_propagate.push_back(p);
                }
            },
            Err(e) => {
                warn!("Client ({}) poll error: {:?}", *client.id, e);
                client.rtc.disconnect();
                return Instant::now();
            }
        }
    }
}

fn read_socket_input<'a>(socket: &UdpSocket, buf: &'a mut [u8]) -> Option<Input<'a>> {
    match socket.recv_from(buf) {
        Ok((n, source)) => {
            let destination = socket.local_addr().unwrap();
            let receive = Receive::new(Protocol::Udp, source, destination, &buf[..n]).ok()?;
            Some(Input::Receive(Instant::now(), receive))
        }
        Err(e) => match e.kind() {
            ErrorKind::TimedOut | ErrorKind::WouldBlock => None,
            _ => panic!("Error reading UDP socket: {e:?}"),
        },
    }
}

// ─── Client ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClientId(u64);

static CLIENT_COUNT: AtomicU64 = AtomicU64::new(0);

impl ClientId {
    fn new() -> Self {
        ClientId(CLIENT_COUNT.fetch_add(1, Ordering::SeqCst))
    }
}

impl std::fmt::Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Deref for ClientId {
    type Target = u64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
struct Client {
    id: ClientId,
    rtc: Rtc,
    pending: Option<SdpPendingOffer>,
    cid_sdp: Option<ChannelId>,       // "offer/answer" channel for SDP renegotiation
    cid_e2ee: Option<ChannelId>,      // "e2ee-keys" channel for key exchange relay
    tracks_in: Vec<TrackInEntry>,
    tracks_out: Vec<TrackOut>,
}

#[derive(Debug)]
struct TrackInEntry {
    id: Arc<TrackIn>,
    last_keyframe_request: Option<Instant>,
}

#[derive(Debug)]
struct TrackIn {
    origin: ClientId,
    mid: Mid,
    kind: MediaKind,
}

#[derive(Debug)]
struct TrackOut {
    track_in: Weak<TrackIn>,
    state: TrackOutState,
}

#[derive(Debug)]
enum TrackOutState {
    ToOpen,
    Negotiating(Mid),
    Open(Mid),
}

impl TrackOut {
    fn mid(&self) -> Option<Mid> {
        match &self.state {
            TrackOutState::Open(mid) => Some(*mid),
            _ => None,
        }
    }
}

#[derive(Debug)]
enum Propagated {
    Noop,
    TrackOpen(ClientId, Weak<TrackIn>),
    /// Opaque RTP packet to forward (E2EE mode)
    RtpPacket(ClientId, Mid, Box<RtpPacketData>),
    KeyframeRequest(ClientId, KeyframeRequest, Mid),
    /// DataChannel data to relay (E2EE key exchange)
    ChannelData(ClientId, ChannelData),
}

/// Minimal RTP packet data needed for forwarding
#[derive(Debug)]
struct RtpPacketData {
    seq_no: str0m::rtp::SeqNo,
    time: str0m::media::MediaTime,
    header: str0m::rtp::RtpHeader,
    payload: Vec<u8>,
    timestamp: Instant,
    nackable: bool,
}

impl Client {
    fn accepts(&self, input: &Input) -> bool {
        self.rtc.accepts(input)
    }

    fn handle_input(&mut self, input: Input) {
        if let Err(e) = self.rtc.handle_input(input) {
            warn!("Client ({}) input error: {:?}", *self.id, e);
            self.rtc.disconnect();
        }
    }

    fn handle_event(&mut self, event: Event) -> Propagated {
        match event {
            Event::IceConnectionStateChange(state) => {
                info!("Client ({}) ICE state: {:?}", *self.id, state);
                if state == IceConnectionState::Disconnected {
                    self.rtc.disconnect();
                }
                Propagated::Noop
            }
            Event::MediaAdded(media) => {
                info!(
                    "Client ({}) media added: {:?} {:?} {:?}",
                    *self.id, media.mid, media.kind, media.direction
                );

                // Register tracks where the remote is sending TO us (RecvOnly or SendRecv)
                if media.direction.is_receiving() {
                    let track_in = Arc::new(TrackIn {
                        origin: self.id,
                        mid: media.mid,
                        kind: media.kind,
                    });

                    self.tracks_in.push(TrackInEntry {
                        id: track_in.clone(),
                        last_keyframe_request: None,
                    });

                    return Propagated::TrackOpen(self.id, Arc::downgrade(&track_in));
                }

                Propagated::Noop
            }
            // E2EE: Handle raw RTP packets (opaque payload forwarding)
            Event::RtpPacket(packet) => self.handle_rtp_packet_in(packet),

            Event::ChannelOpen(cid, label) => {
                info!("Client ({}) channel open: {} ({:?})", *self.id, label, cid);
                if label == "offer/answer" {
                    self.cid_sdp = Some(cid);
                } else {
                    // E2EE key exchange channel (or any other channel)
                    self.cid_e2ee = Some(cid);
                }
                Propagated::Noop
            }
            Event::ChannelData(data) => {
                // Check if this is from the SDP channel or the E2EE channel
                if Some(data.id) == self.cid_sdp {
                    // SDP renegotiation — process internally, don't relay
                    self.handle_sdp_channel_data(&data);
                    Propagated::Noop
                } else {
                    // E2EE key exchange — relay to all other clients
                    Propagated::ChannelData(self.id, data)
                }
            }
            Event::ChannelClose(cid) => {
                info!("Client ({}) channel closed: {:?}", *self.id, cid);
                Propagated::Noop
            }
            Event::KeyframeRequest(req) => {
                // Forward keyframe request to the originating client
                if let Some(track_out) = self.tracks_out.iter().find(|t| {
                    t.mid() == Some(req.mid)
                }) {
                    if let Some(track_in) = track_out.track_in.upgrade() {
                        return Propagated::KeyframeRequest(
                            track_in.origin,
                            req,
                            track_in.mid,
                        );
                    }
                }
                Propagated::Noop
            }
            Event::StreamPaused(paused) => {
                info!(
                    "Client ({}) stream {:?} paused={}",
                    *self.id, paused.ssrc, paused.paused
                );
                Propagated::Noop
            }
            Event::EgressBitrateEstimate(bwe) => {
                info!("Client ({}) BWE: {:?}", *self.id, bwe);
                Propagated::Noop
            }
            _ => Propagated::Noop,
        }
    }

    /// Handle incoming RTP packet — extract data for forwarding
    fn handle_rtp_packet_in(&mut self, packet: RtpPacket) -> Propagated {
        // Find which incoming track this packet belongs to
        let mid = packet.header.ext_vals.mid;

        // Match to a known incoming track by MID
        let origin_mid = if let Some(mid) = mid {
            mid
        } else {
            // Try to find by looking at existing tracks
            if let Some(entry) = self.tracks_in.first() {
                entry.id.mid
            } else {
                return Propagated::Noop;
            }
        };

        Propagated::RtpPacket(
            self.id,
            origin_mid,
            Box::new(RtpPacketData {
                seq_no: packet.seq_no,
                time: packet.time,
                header: packet.header,
                payload: packet.payload,
                timestamp: packet.timestamp,
                nackable: true,
            }),
        )
    }

    /// Forward an opaque RTP packet to this client
    fn handle_rtp_packet_out(&mut self, origin: ClientId, mid_in: Mid, packet: &RtpPacketData) {
        // Find outgoing track corresponding to this incoming media
        let Some(out_mid) = self
            .tracks_out
            .iter()
            .find(|o| {
                o.track_in
                    .upgrade()
                    .filter(|i| i.origin == origin && i.mid == mid_in)
                    .is_some()
            })
            .and_then(|o| o.mid())
        else {
            return;
        };

        // Get the stream_tx for this outgoing mid
        let mut direct = self.rtc.direct_api();

        let Some(stream) = direct.stream_tx_by_mid(out_mid, None) else {
            return;
        };

        // Forward the opaque payload using write_rtp
        let ext_vals = packet.header.ext_vals.clone();
        if let Err(e) = stream.write_rtp(
            packet.header.payload_type,
            packet.seq_no,
            packet.header.timestamp,
            packet.timestamp,
            packet.header.marker,
            ext_vals,
            packet.nackable,
            packet.payload.clone(),
        ) {
            warn!("Client ({}) write_rtp failed: {:?}", self.id.0, e);
        }
    }

    fn handle_track_open(&mut self, track: Weak<TrackIn>) {
        self.tracks_out.push(TrackOut {
            track_in: track,
            state: TrackOutState::ToOpen,
        });
        self.negotiate_if_needed();
    }

    fn handle_keyframe_request(&mut self, req: &KeyframeRequest, mid_in: Mid) {
        if !self.tracks_in.iter().any(|t| t.id.mid == mid_in) {
            return;
        }

        // In RTP mode, use direct API for keyframe requests
        let mut direct = self.rtc.direct_api();

        if let Some(stream) = direct.stream_rx_by_mid(mid_in, None) {
            stream.request_keyframe(req.kind);
        }
    }

    fn relay_channel_data(&mut self, data: &ChannelData) {
        let Some(cid) = self.cid_e2ee else { return };
        let Some(mut channel) = self.rtc.channel(cid) else { return };

        if let Err(e) = channel.write(data.binary, &data.data) {
            warn!("Client ({}) relay channel data failed: {:?}", *self.id, e);
        }
    }

    fn handle_sdp_channel_data(&mut self, data: &ChannelData) {
        let text = match std::str::from_utf8(&data.data) {
            Ok(t) => t,
            Err(_) => return,
        };

        let json: serde_json::Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(_) => return,
        };

        let msg_type = json.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match msg_type {
            "offer" => {
                info!("Client ({}) received SDP offer via DataChannel", *self.id);
                match serde_json::from_str::<SdpOffer>(text) {
                    Ok(offer) => {
                        match self.rtc.sdp_api().accept_offer(offer) {
                            Ok(answer) => {
                                let json = serde_json::to_string(&answer).unwrap();
                                if let Some(cid) = self.cid_sdp {
                                    if let Some(mut channel) = self.rtc.channel(cid) {
                                        channel.write(false, json.as_bytes()).ok();
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Client ({}) accept offer failed: {:?}", *self.id, e);
                            }
                        }
                    }
                    Err(e) => warn!("Client ({}) parse offer failed: {:?}", *self.id, e),
                }
            }
            "answer" => {
                info!("Client ({}) received SDP answer via DataChannel", *self.id);
                if let Some(pending) = self.pending.take() {
                    match serde_json::from_str::<SdpAnswer>(text) {
                        Ok(answer) => {
                            if let Err(e) = self.rtc.sdp_api().accept_answer(pending, answer) {
                                warn!("Client ({}) accept answer failed: {:?}", *self.id, e);
                            } else {
                                // Mark negotiating tracks as open
                                for track in &mut self.tracks_out {
                                    if let TrackOutState::Negotiating(mid) = track.state {
                                        track.state = TrackOutState::Open(mid);
                                    }
                                }
                                // Trigger further negotiation if more tracks are pending
                                self.negotiate_if_needed();
                            }
                        }
                        Err(e) => warn!("Client ({}) parse answer failed: {:?}", *self.id, e),
                    }
                }
            }
            _ => {
                info!("Client ({}) unknown SDP channel message type: {}", *self.id, msg_type);
            }
        }
    }

    fn negotiate_if_needed(&mut self) -> bool {
        if self.cid_sdp.is_none() || self.pending.is_some() {
            return false;
        }

        let mut change = self.rtc.sdp_api();

        for track in &mut self.tracks_out {
            if let TrackOutState::ToOpen = track.state {
                if let Some(track_in) = track.track_in.upgrade() {
                    let stream_id = track_in.origin.0.to_string();
                    let mid = change.add_media(
                        track_in.kind,
                        Direction::SendOnly,
                        Some(stream_id),
                        None,
                        None,
                    );
                    track.state = TrackOutState::Negotiating(mid);
                }
            }
        }

        if !change.has_changes() {
            return false;
        }

        let Some((offer, pending)) = change.apply() else {
            return false;
        };

        let Some(mut channel) = self.cid_sdp.and_then(|id| self.rtc.channel(id)) else {
            return false;
        };

        let json = serde_json::to_string(&offer).unwrap();
        channel
            .write(false, json.as_bytes())
            .expect("to write offer");

        self.pending = Some(pending);
        true
    }
}
