//! PERC Double Encryption SFU Example (RFC 8723 / RFC 8871)
//!
//! Phase 2 of the PERC E2EE architecture. This SFU uses normal DTLS-SRTP
//! (hop-by-hop encryption) with each client independently, while the E2E
//! encrypted payload passes through opaquely.
//!
//! ## How it differs from `e2ee_tunnel`
//!
//! - **Normal DTLS-SRTP** — SFU terminates DTLS with each client independently.
//!   Each client has unique HBH SRTP keys with the SFU.
//! - **rtp_mode** — SFU receives decrypted RTP payloads and forwards them.
//!   The inner E2E encrypted payload is treated as opaque bytes.
//! - **OHB** — Original Header Block (RFC 8723 §4) tracks any RTP header
//!   modifications the SFU makes during forwarding.
//! - **No fingerprint swapping** — each client does its own DTLS with the SFU.
//!
//! ## Signaling Protocol
//!
//! 1. Client A:  `POST /offer`  → `{room_id, status: "waiting"}`
//! 2. Client B:  `POST /offer`  → `{room_id, status: "paired", answer: <SDP>}`
//! 3. Client A:  `GET /answer?room=<id>` → `{answer: <SDP>}`
//!
//! ## Usage
//!
//! ```text
//! cargo run --example e2ee_perc --no-default-features --features "wincrypto,examples"
//! ```

#[macro_use]
extern crate tracing;

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rouille::Server;
use rouille::{Request, Response};
use str0m::change::{SdpAnswer, SdpOffer};
use str0m::crypto::from_feature_flags;
use str0m::media::{KeyframeRequestKind, MediaKind, Mid, Pt};
use str0m::net::{Protocol, Receive};
use str0m::rtp::{ExtensionValues, RtpPacket, SeqNo, Ssrc};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc};

mod util;

fn init_log(level: &str) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let default = format!("e2ee_perc={level},str0m=warn");
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(env_filter)
        .init();
}

// ─── Room State ───────────────────────────────────────────

/// A room pairs two clients. Each has independent DTLS-SRTP with the SFU.
struct Room {
    rtc_a: Option<Rtc>,
    answer_a: Option<SdpAnswer>,
    /// A's media info: (mid, kind) for each m-line
    media_a: Vec<(Mid, MediaKind)>,
    rtc_b: Option<Rtc>,
    /// B's media info
    media_b: Vec<(Mid, MediaKind)>,
}

type Rooms = Arc<Mutex<HashMap<String, Room>>>;

/// Message to the run loop: a paired room is ready
struct PairedRoom {
    room_id: String,
    rtc_a: Rtc,
    rtc_b: Rtc,
    media_a: Vec<(Mid, MediaKind)>,
    media_b: Vec<(Mid, MediaKind)>,
}

// ─── SDP Helpers ──────────────────────────────────────────

/// Extract media type (audio/video) and mid from SDP m-lines.
fn extract_media_info(sdp: &str) -> Vec<(Mid, MediaKind)> {
    let mut result = Vec::new();
    let mut current_kind: Option<MediaKind> = None;

    for line in sdp.lines() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.starts_with("m=audio") {
            current_kind = Some(MediaKind::Audio);
        } else if trimmed.starts_with("m=video") {
            current_kind = Some(MediaKind::Video);
        } else if let Some(mid_str) = trimmed.strip_prefix("a=mid:") {
            if let Some(kind) = current_kind {
                result.push((mid_str.into(), kind));
            }
        }
    }
    result
}

// ─── HTTP Handlers ────────────────────────────────────────

pub fn main() {
    let (cfg, cfg_sources) = util::load_config("sfu");
    let log_level = util::cfg_str(&cfg, "logLevel", "info");
    init_log(&log_level);
    from_feature_flags().install_process_default();

    if !cfg_sources.is_empty() {
        info!("Config loaded from: {}", cfg_sources.join(", "));
    }

    let certificate = include_bytes!("cer.pem").to_vec();
    let private_key = include_bytes!("key.pem").to_vec();

    let host_addr = util::select_host_address();

    let (tx, rx) = mpsc::sync_channel::<PairedRoom>(4);

    // UDP bind: config udpHost (default to discovered host) + udpPort (0=random).
    let udp_host = util::cfg_str(&cfg, "udpHost", &host_addr.to_string());
    let udp_port = util::cfg_u64(&cfg, "udpPort", 0);
    let socket =
        UdpSocket::bind(format!("{udp_host}:{udp_port}")).expect("binding the UDP port");
    let addr = socket.local_addr().expect("a local socket address");
    info!("Bound UDP port: {}", addr);

    let rooms: Rooms = Arc::new(Mutex::new(HashMap::new()));

    let stats_interval = util::cfg_u64(&cfg, "statsIntervalSec", 5);
    let wire_log = util::cfg_bool(&cfg, "diagnostics.wireLog", true);
    thread::spawn(move || run(socket, rx, stats_interval, wire_log));

    let http_host = util::cfg_str(&cfg, "httpHost", "0.0.0.0");
    let http_port = util::cfg_u64(&cfg, "httpPort", 3000);
    let server = Server::new_ssl(
        format!("{http_host}:{http_port}"),
        move |request| web_request(request, addr, tx.clone(), rooms.clone()),
        certificate,
        private_key,
    )
    .expect("starting the web server");

    let port = server.server_addr().port();
    info!(
        "PERC SFU ready at https://{:?}:{}",
        addr.ip(),
        port
    );
    info!("  POST /offer          — submit SDP offer (JSON)");
    info!("  GET  /answer?room=X  — poll for SDP answer");

    server.run();
}

fn web_request(
    request: &Request,
    addr: SocketAddr,
    tx: SyncSender<PairedRoom>,
    rooms: Rooms,
) -> Response {
    let cors = vec![
        ("Access-Control-Allow-Origin".to_string(), "*".to_string()),
        (
            "Access-Control-Allow-Methods".to_string(),
            "GET, POST, OPTIONS".to_string(),
        ),
        (
            "Access-Control-Allow-Headers".to_string(),
            "Content-Type".to_string(),
        ),
    ];

    if request.method() == "OPTIONS" {
        let mut resp = Response::empty_204();
        for (k, v) in &cors {
            resp = resp.with_additional_header(k.clone(), v.clone());
        }
        return resp;
    }

    let mut resp = match (request.method(), request.url().as_str()) {
        ("POST", "/offer") => handle_offer(request, addr, tx, rooms),
        ("GET", url) if url.starts_with("/answer") => handle_get_answer(request, rooms),
        _ => Response::json(&serde_json::json!({"error": "not found"})).with_status_code(404),
    };

    for (k, v) in cors {
        resp = resp.with_additional_header(k, v);
    }
    resp
}

fn handle_offer(
    request: &Request,
    addr: SocketAddr,
    tx: SyncSender<PairedRoom>,
    rooms: Rooms,
) -> Response {
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

    let offer_sdp_str = offer.to_sdp_string();
    let media_info = extract_media_info(&offer_sdp_str);
    info!("Received offer with {} media lines", media_info.len());

    let mut rooms_lock = rooms.lock().unwrap();

    // Find a room waiting for a second client
    let waiting_room_id = rooms_lock
        .iter()
        .find(|(_, room)| room.rtc_b.is_none())
        .map(|(id, _)| id.clone());

    if let Some(room_id) = waiting_room_id {
        // Second client joining — pair them
        info!("Pairing client B into room {}", room_id);

        let room = rooms_lock.get_mut(&room_id).unwrap();

        // Create Rtc for client B — normal DTLS-SRTP mode (no tunnel)
        let mut rtc_b = Rtc::builder()
            .set_rtp_mode(true)
            .build(Instant::now());

        let candidate = Candidate::host(addr, "udp").expect("a host candidate");
        rtc_b.add_local_candidate(candidate).unwrap();

        let answer_b = match rtc_b.sdp_api().accept_offer(offer) {
            Ok(a) => a,
            Err(e) => {
                error!("Failed to accept offer B: {:?}", e);
                return Response::json(&serde_json::json!({"error": format!("accept failed: {e}")}))
                    .with_status_code(500);
            }
        };

        let rtc_a = room.rtc_a.take().unwrap();
        let media_a = room.media_a.clone();

        // Store placeholder so room appears paired (answer_a stays for polling)
        room.rtc_b = Some(Rtc::new(Instant::now()));
        room.media_b = media_info.clone();

        // Send to run loop
        if let Err(e) = tx.send(PairedRoom {
            room_id: room_id.clone(),
            rtc_a,
            rtc_b,
            media_a,
            media_b: media_info,
        }) {
            error!("Failed to send paired room: {:?}", e);
            return Response::json(&serde_json::json!({"error": "server busy"}))
                .with_status_code(503);
        }

        // Return answer for B immediately
        let body = serde_json::to_vec(&answer_b).expect("answer to serialize");
        Response::from_data("application/json", body)
    } else {
        // First client — create a new room
        let room_id = format!("{:08x}", fastrand::u32(..));
        info!("Client A created room {}", room_id);

        let mut rtc_a = Rtc::builder()
            .set_rtp_mode(true)
            .build(Instant::now());

        let candidate = Candidate::host(addr, "udp").expect("a host candidate");
        rtc_a.add_local_candidate(candidate).unwrap();

        let answer_a = match rtc_a.sdp_api().accept_offer(offer) {
            Ok(a) => a,
            Err(e) => {
                error!("Failed to accept offer A: {:?}", e);
                return Response::json(&serde_json::json!({"error": format!("accept failed: {e}")}))
                    .with_status_code(500);
            }
        };

        rooms_lock.insert(
            room_id.clone(),
            Room {
                rtc_a: Some(rtc_a),
                answer_a: Some(answer_a),
                media_a: media_info,
                rtc_b: None,
                media_b: vec![],
            },
        );

        Response::json(&serde_json::json!({
            "status": "waiting",
            "room_id": room_id,
            "message": "Waiting for peer. Poll GET /answer?room=<room_id> for your SDP answer."
        }))
    }
}

fn handle_get_answer(request: &Request, rooms: Rooms) -> Response {
    let room_id = request.get_param("room").unwrap_or_default();

    if room_id.is_empty() {
        return Response::json(&serde_json::json!({"error": "missing ?room= parameter"}))
            .with_status_code(400);
    }

    let mut rooms_lock = rooms.lock().unwrap();

    let Some(room) = rooms_lock.get_mut(&room_id) else {
        return Response::json(&serde_json::json!({"error": "room not found"}))
            .with_status_code(404);
    };

    if room.rtc_b.is_none() {
        return Response::json(&serde_json::json!({
            "status": "waiting",
            "message": "Peer has not joined yet."
        }))
        .with_status_code(202);
    }

    if let Some(answer) = room.answer_a.take() {
        info!("Returning answer for client A in room {}", room_id);
        let body = serde_json::to_vec(&answer).expect("answer to serialize");
        Response::from_data("application/json", body)
    } else {
        Response::json(
            &serde_json::json!({"status": "answered", "message": "Answer already retrieved."}),
        )
    }
}

// ─── Main Run Loop ────────────────────────────────────────

struct PercClient {
    id: usize,
    room_id: String,
    role: char, // 'A' or 'B'
    rtc: Rtc,
    ice_connected: bool,
    dtls_connected: bool,
    /// Media lines from this client's SDP offer: (mid, kind)
    media: Vec<(Mid, MediaKind)>,
    /// SSRC → media kind mapping, learned from incoming RTP packets
    rx_ssrc_kind: HashMap<Ssrc, MediaKind>,
    // Forwarding stats
    fwd_rtp: u64,
}

/// Find the peer's tx stream mid for a given media kind.
fn find_tx_mid_for_kind(
    peer_media: &[(Mid, MediaKind)],
    kind: MediaKind,
) -> Option<Mid> {
    peer_media
        .iter()
        .find(|(_, k)| *k == kind)
        .map(|(mid, _)| *mid)
}

/// An RTP packet to forward from one client to another.
struct ForwardPacket {
    room_id: String,
    sender_role: char,
    media_kind: MediaKind,
    // RTP header fields (from sender)
    pt: Pt,
    seq_no: SeqNo,
    timestamp: u32,
    marker: bool,
    ext_vals: ExtensionValues,
    /// The RTP payload — contains E2E ciphertext (opaque to SFU) + OHB
    payload: Vec<u8>,
}

/// A keyframe (PLI/FIR) request to relay back to the original sender.
struct KeyframeReq {
    room_id: String,
    requester_role: char,
    kind: KeyframeRequestKind,
}

fn run(socket: UdpSocket, rx: Receiver<PairedRoom>, stats_interval: u64, wire_log: bool) -> ! {
    let mut clients: Vec<PercClient> = vec![];
    let mut buf = vec![0; 2000];
    let mut next_id: usize = 0;
    let mut last_stats = Instant::now();
    // DIAG: track distinct (ssrc, pt) seen on the wire to confirm what media
    // actually arrives at the SFU, independent of str0m's SSRC discovery.
    let mut seen_wire: std::collections::HashSet<(u32, u8)> = std::collections::HashSet::new();

    loop {
        // Accept paired rooms
        while let Ok(paired) = rx.try_recv() {
            let id_a = next_id;
            next_id += 1;
            let id_b = next_id;
            next_id += 1;

            info!(
                "Room {} active: client A={}, client B={}",
                paired.room_id, id_a, id_b
            );

            clients.push(PercClient {
                id: id_a,
                room_id: paired.room_id.clone(),
                role: 'A',
                rtc: paired.rtc_a,
                ice_connected: false,
                dtls_connected: false,
                media: paired.media_a,
                rx_ssrc_kind: HashMap::new(),
                fwd_rtp: 0,
            });
            clients.push(PercClient {
                id: id_b,
                room_id: paired.room_id,
                role: 'B',
                rtc: paired.rtc_b,
                ice_connected: false,
                dtls_connected: false,
                media: paired.media_b,
                rx_ssrc_kind: HashMap::new(),
                fwd_rtp: 0,
            });
        }

        // Remove dead clients
        clients.retain(|c| c.rtc.is_alive());

        // Poll all clients and collect packets to forward
        let mut forwards: Vec<ForwardPacket> = Vec::new();
        // Keyframe (PLI/FIR) requests to relay back to the original sender.
        let mut keyframe_reqs: Vec<KeyframeReq> = Vec::new();

        for client in clients.iter_mut() {
            loop {
                match client.rtc.poll_output() {
                    Ok(Output::Timeout(_)) => break,
                    Ok(Output::Transmit(t)) => {
                        if let Err(e) = socket.send_to(&t.contents, t.destination) {
                            if e.kind() != ErrorKind::TimedOut
                                && e.kind() != ErrorKind::ConnectionReset
                                && e.kind() != ErrorKind::WouldBlock
                            {
                                error!("Send error to {}: {:?}", t.destination, e);
                            }
                        }
                    }
                    Ok(Output::Event(Event::IceConnectionStateChange(state))) => {
                        info!(
                            "Room {} Client {} ({}): ICE {:?}",
                            client.room_id, client.id, client.role, state
                        );
                        client.ice_connected = matches!(
                            state,
                            IceConnectionState::Connected | IceConnectionState::Completed
                        );
                    }
                    Ok(Output::Event(Event::Connected)) => {
                        info!(
                            "Room {} Client {} ({}): DTLS connected",
                            client.room_id, client.id, client.role
                        );
                        client.dtls_connected = true;
                    }
                    Ok(Output::Event(Event::MediaAdded(media_added))) => {
                        info!(
                            "Room {} Client {} ({}): media added mid={} kind={:?} dir={:?}",
                            client.room_id,
                            client.id,
                            client.role,
                            media_added.mid,
                            media_added.kind,
                            media_added.direction
                        );
                    }
                    Ok(Output::Event(Event::RtpPacket(pkt))) => {
                        let ssrc: Ssrc = pkt.header.ssrc;

                        // Learn SSRC → media kind mapping from incoming packets
                        let kind = if !client.rx_ssrc_kind.contains_key(&ssrc) {
                            // Determine media kind from the mid in the header extensions
                            // or from the media info we extracted from SDP
                            let kind = determine_media_kind(client, &pkt);
                            client.rx_ssrc_kind.insert(ssrc, kind);
                            info!(
                                "Room {} Client {} ({}): learned SSRC {} → {:?}",
                                client.room_id, client.id, client.role, ssrc, kind
                            );
                            kind
                        } else {
                            *client.rx_ssrc_kind.get(&ssrc).unwrap()
                        };

                        debug!(
                            "Room {} {} → {:?} RTP seq={} ts={} pt={} marker={} payload={} bytes",
                            client.room_id,
                            client.role,
                            kind,
                            pkt.header.sequence_number,
                            pkt.header.timestamp,
                            pkt.header.payload_type,
                            pkt.header.marker,
                            pkt.payload.len(),
                        );

                        forwards.push(ForwardPacket {
                            room_id: client.room_id.clone(),
                            sender_role: client.role,
                            media_kind: kind,
                            pt: pkt.header.payload_type,
                            seq_no: pkt.seq_no,
                            timestamp: pkt.header.timestamp,
                            marker: pkt.header.marker,
                            ext_vals: pkt.header.ext_vals,
                            payload: pkt.payload,
                        });
                    }
                    Ok(Output::Event(Event::KeyframeRequest(req))) => {
                        debug!(
                            "Room {} Client {} ({}): keyframe request {:?}",
                            client.room_id, client.id, client.role, req
                        );
                        // The request arrives on this receiver's perspective. We
                        // relay it back to the ORIGINAL SENDER (the peer in the
                        // same room) so its encoder emits a fresh keyframe. The
                        // peer is identified by the opposite role; the actual rx
                        // SSRC is resolved later when we have a mutable handle to
                        // the sender.
                        keyframe_reqs.push(KeyframeReq {
                            room_id: client.room_id.clone(),
                            requester_role: client.role,
                            kind: req.kind,
                        });
                    }
                    Ok(Output::Event(e)) => {
                        debug!(
                            "Room {} Client {} ({}): {:?}",
                            client.room_id, client.id, client.role, e
                        );
                    }
                    Err(e) => {
                        error!(
                            "Room {} Client {} ({}): error {:?}",
                            client.room_id, client.id, client.role, e
                        );
                        client.rtc.disconnect();
                        break;
                    }
                }
            }
        }

        // Forward RTP packets: sender → peer in same room
        for fwd in forwards {
            let peer_role = if fwd.sender_role == 'A' { 'B' } else { 'A' };
            if let Some(peer) = clients
                .iter_mut()
                .find(|c| c.room_id == fwd.room_id && c.role == peer_role)
            {
                if !peer.dtls_connected {
                    continue;
                }

                // Find the peer's tx stream for the same media kind
                let tx_mid = find_tx_mid_for_kind(&peer.media, fwd.media_kind);
                let Some(mid) = tx_mid else {
                    debug!("No tx mid for {:?} on peer {}", fwd.media_kind, peer.role);
                    continue;
                };

                // The payload is opaque E2E encrypted data, produced by the
                // client's frame-level transform (encryption happens on the
                // whole encoded frame, before RTP packetization). Because the
                // SFU forwards at the RTP-packet level, a single encoded frame
                // may span many packets. We MUST NOT append a per-packet OHB
                // here: doing so would inject bytes at every packet boundary
                // inside the frame, which the receiver reassembles into the
                // (now corrupted) ciphertext, breaking GCM auth for any
                // multi-packet frame (i.e. all video keyframes).
                //
                // The SFU does not rewrite PT/SEQ/marker, so the OHB would be
                // empty anyway. Forward the payload unmodified.
                let mut direct = peer.rtc.direct_api();
                if let Some(stream) = direct.stream_tx_by_mid(mid, None) {
                    match stream.write_rtp(
                        fwd.pt,
                        fwd.seq_no,
                        fwd.timestamp,
                        Instant::now(),
                        fwd.marker,
                        fwd.ext_vals,
                        true, // nackable — video packets should be nackable
                        fwd.payload,
                    ) {
                        Ok(_) => {
                            // Count stats on the sender side
                            drop(direct);
                            peer.fwd_rtp += 1;
                        }
                        Err(e) => {
                            debug!("write_rtp error for peer {}: {:?}", peer.role, e);
                        }
                    }
                } else {
                    debug!(
                        "No tx stream for mid={} on peer {} (room {})",
                        mid, peer.role, fwd.room_id
                    );
                }
            }
        }

        // Relay keyframe requests (PLI/FIR) back to the original sender. A
        // receiver that joins mid-stream needs a keyframe to start decoding;
        // without this relay its PLIs are dropped and the sender never refreshes.
        for kreq in keyframe_reqs {
            let sender_role = if kreq.requester_role == 'A' { 'B' } else { 'A' };
            if let Some(sender) = clients
                .iter_mut()
                .find(|c| c.room_id == kreq.room_id && c.role == sender_role)
            {
                // Find every video SSRC we receive from this sender and ask for
                // a keyframe on its rx stream.
                let video_ssrcs: Vec<Ssrc> = sender
                    .rx_ssrc_kind
                    .iter()
                    .filter(|(_, k)| **k == MediaKind::Video)
                    .map(|(ssrc, _)| *ssrc)
                    .collect();
                let mut direct = sender.rtc.direct_api();
                for ssrc in video_ssrcs {
                    if let Some(stream) = direct.stream_rx(&ssrc) {
                        stream.request_keyframe(kreq.kind);
                        debug!(
                            "Room {} relayed keyframe request {:?} to sender {} ssrc={}",
                            kreq.room_id, kreq.kind, sender_role, ssrc
                        );
                    }
                }
            }
        }

        // Periodic stats
        if last_stats.elapsed() > Duration::from_secs(stats_interval) {
            for client in clients.iter() {
                if client.fwd_rtp > 0 {
                    info!(
                        "STATS Room {} → {}: forwarded RTP={}",
                        client.room_id, client.role, client.fwd_rtp,
                    );
                }
            }
            last_stats = Instant::now();
        }

        // Read network input
        let timeout = Instant::now() + Duration::from_millis(5);
        let duration = (timeout - Instant::now()).max(Duration::from_millis(1));
        socket
            .set_read_timeout(Some(duration))
            .expect("setting read timeout");

        match socket.recv_from(&mut buf) {
            Ok((n, source)) => {
                let data = &buf[..n];
                // DIAG: peek the cleartext RTP header (SRTP does not encrypt the
                // 12-byte header) to log distinct (ssrc, pt) seen on the wire.
                if wire_log && n >= 12 && (data[0] >> 6) == 2 {
                    let pt_field = data[1] & 0x7f;
                    // RFC 5761: second-byte values 64..=95 indicate RTCP.
                    let is_rtcp = (64..=95).contains(&pt_field);
                    if !is_rtcp {
                        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                        if seen_wire.insert((ssrc, pt_field)) {
                            info!("WIRE: new RTP on wire ssrc={} pt={} from={}", ssrc, pt_field, source);
                        }
                    }
                }
                for client in clients.iter_mut() {
                    let destination = socket.local_addr().unwrap();
                    if let Ok(contents) = data.try_into() {
                        let input = Input::Receive(
                            Instant::now(),
                            Receive {
                                proto: Protocol::Udp,
                                source,
                                destination,
                                contents,
                            },
                        );

                        if client.rtc.accepts(&input) {
                            client.rtc.handle_input(input).ok();
                            break;
                        }
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == ErrorKind::ConnectionReset => {}
            Err(e) if e.kind() == ErrorKind::TimedOut => {}
            Err(e) => {
                error!("Socket error: {:?}", e);
            }
        }

        // Drive timeouts
        let now = Instant::now();
        for client in clients.iter_mut() {
            client.rtc.handle_input(Input::Timeout(now)).ok();
        }
    }
}

/// Determine the media kind for an SSRC by checking the client's Rtc state.
fn determine_media_kind(client: &mut PercClient, pkt: &RtpPacket) -> MediaKind {
    // Preferred: the MID RTP header extension. libwebrtc reliably sends it on
    // the first packets of every SSRC (which is exactly when we classify and
    // then cache the SSRC), so we can map it to the negotiated media kind.
    if let Some(mid) = pkt.header.ext_vals.mid {
        if let Some((_, kind)) = client.media.iter().find(|(m, _)| *m == mid) {
            return *kind;
        }
    }

    // Fallback: ask str0m which mid owns this SSRC (str0m learns the binding
    // from SRTP / the MID extension internally), then map mid → kind.
    let ssrc = pkt.header.ssrc;
    let mid = client.rtc.direct_api().stream_rx(&ssrc).map(|s| s.mid());
    if let Some(mid) = mid {
        if let Some((_, kind)) = client.media.iter().find(|(m, _)| *m == mid) {
            return *kind;
        }
    }

    // Last resort: assume video (the higher-bandwidth stream). This should not
    // happen in practice once the MID extension is observed.
    MediaKind::Video
}
