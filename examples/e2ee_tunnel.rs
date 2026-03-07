//! E2EE Tunnel SFU Example
//!
//! A 1:1 tunnel-mode SFU that forwards DTLS/SRTP/SRTCP packets
//! between two clients without decrypting them. The SFU only
//! terminates ICE for NAT traversal — DTLS handshake and SRTP
//! encryption happen end-to-end between the two clients.
//!
//! This is Phase 1 of the PERC E2EE architecture (RFC 8871).
//!
//! ## Signaling Protocol
//!
//! 1. Client A:  `POST /offer`  → body = SDP offer JSON → `{room_id, status: "waiting"}`
//! 2. Client B:  `POST /offer`  → body = SDP offer JSON → `{room_id, status: "paired", answer: <SDP>}`
//! 3. Client A:  `GET /answer?room=<id>` → `{answer: <SDP>}`
//!
//! The SFU swaps DTLS fingerprints so each client verifies the *peer's* certificate,
//! and assigns DTLS roles (A=server/passive, B=client/active).
//!
//! ## Usage
//!
//! ```text
//! cargo run --example e2ee_tunnel --no-default-features --features "wincrypto,examples"
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
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc, TunnelPacketType};

mod util;

fn init_log() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("e2ee_tunnel=info,str0m=info"));

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(env_filter)
        .init();
}

// ─── Room State ───────────────────────────────────────────

/// A room pairs two clients for tunnel-mode forwarding.
struct Room {
    /// First client's SDP offer (raw SDP string for fingerprint extraction)
    offer_a_sdp: String,
    /// Rtc instance for client A (already accepted offer, doing ICE)
    rtc_a: Option<Rtc>,
    /// SDP answer for client A (available after pairing, with B's fingerprint)
    answer_a: Option<SdpAnswer>,
    /// Rtc instance for client B
    rtc_b: Option<Rtc>,
}

type Rooms = Arc<Mutex<HashMap<String, Room>>>;

/// Message to the run loop: a paired room is ready
struct PairedRoom {
    room_id: String,
    rtc_a: Rtc,
    rtc_b: Rtc,
}

// ─── SDP Manipulation ─────────────────────────────────────

/// Extract the DTLS fingerprint line from an SDP string.
/// Returns the full `a=fingerprint:...` value (e.g. "sha-256 AB:CD:EF:...")
fn extract_fingerprint(sdp: &str) -> Option<String> {
    for line in sdp.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with("a=fingerprint:") {
            return Some(line["a=fingerprint:".len()..].to_string());
        }
    }
    None
}

/// Replace the DTLS fingerprint in an SDP string with a new one.
fn replace_fingerprint(sdp: &str, new_fingerprint: &str) -> String {
    let mut result = String::with_capacity(sdp.len());
    for line in sdp.lines() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.starts_with("a=fingerprint:") {
            result.push_str(&format!("a=fingerprint:{}", new_fingerprint));
        } else {
            result.push_str(trimmed);
        }
        result.push_str("\r\n");
    }
    result
}

/// Change the DTLS setup role in an SDP string.
/// `new_setup` should be "active", "passive", or "actpass".
fn replace_setup(sdp: &str, new_setup: &str) -> String {
    let mut result = String::with_capacity(sdp.len());
    for line in sdp.lines() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.starts_with("a=setup:") {
            result.push_str(&format!("a=setup:{}", new_setup));
        } else {
            result.push_str(trimmed);
        }
        result.push_str("\r\n");
    }
    result
}

/// Modify an SDP answer for tunnel mode:
/// - Replace the SFU's fingerprint with the peer's fingerprint
/// - Set the DTLS role
/// - Replace the SFU's SSRCs with the peer's SSRCs (so receiver expects correct SSRCs)
fn patch_answer_sdp(
    answer_sdp: &str,
    peer_fingerprint: &str,
    setup_role: &str,
    peer_offer_sdp: &str,
) -> String {
    let patched = replace_fingerprint(answer_sdp, peer_fingerprint);
    let patched = replace_setup(&patched, setup_role);
    replace_ssrc_lines(&patched, peer_offer_sdp)
}

/// Extract `a=ssrc:` and `a=ssrc-group:` lines from each media section of `src_sdp`,
/// and replace the corresponding lines in `dst_sdp`.
///
/// This ensures the receiver's SDP contains the sender's actual SSRCs, so libwebrtc
/// creates receive streams with the correct SSRC → track → video sink mapping.
fn replace_ssrc_lines(dst_sdp: &str, src_sdp: &str) -> String {
    let dst_sections = split_media_sections(dst_sdp);
    let src_sections = split_media_sections(src_sdp);

    let mut result = String::with_capacity(dst_sdp.len());

    // Session-level lines (before first m=)
    result.push_str(&dst_sections[0]);

    // For each media section in the answer, replace a=ssrc/a=ssrc-group lines
    // with those from the corresponding section of the peer's offer
    for i in 1..dst_sections.len() {
        let dst_section = &dst_sections[i];

        // Find matching source section by media type (audio/video)
        let dst_media_type = media_type_from_section(dst_section);
        let src_ssrc_lines = src_sections
            .iter()
            .skip(1)
            .find(|s| media_type_from_section(s) == dst_media_type)
            .map(|s| extract_ssrc_block(s))
            .unwrap_or_default();

        // Write all lines except a=ssrc: and a=ssrc-group:, then append peer's
        for line in dst_section.lines() {
            let trimmed = line.trim_end_matches('\r');
            if trimmed.starts_with("a=ssrc:") || trimmed.starts_with("a=ssrc-group:") {
                continue; // skip SFU's SSRCs
            }
            result.push_str(trimmed);
            result.push_str("\r\n");
        }

        // Append peer's SSRC lines
        for ssrc_line in &src_ssrc_lines {
            result.push_str(ssrc_line);
            result.push_str("\r\n");
        }
    }

    result
}

/// Split an SDP string into sections: [session, media0, media1, ...]
fn split_media_sections(sdp: &str) -> Vec<String> {
    let mut sections = Vec::new();
    let mut current = String::new();

    for line in sdp.lines() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.starts_with("m=") && !current.is_empty() {
            sections.push(std::mem::take(&mut current));
        }
        current.push_str(trimmed);
        current.push_str("\r\n");
    }
    if !current.is_empty() {
        sections.push(current);
    }
    sections
}

/// Get the media type (e.g. "audio", "video") from a media section starting with "m=..."
fn media_type_from_section(section: &str) -> &str {
    for line in section.lines() {
        let trimmed = line.trim_end_matches('\r');
        if let Some(rest) = trimmed.strip_prefix("m=") {
            return rest.split_whitespace().next().unwrap_or("");
        }
    }
    ""
}

/// Extract all `a=ssrc:` and `a=ssrc-group:` lines from a media section
fn extract_ssrc_block(section: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for line in section.lines() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.starts_with("a=ssrc:") || trimmed.starts_with("a=ssrc-group:") {
            lines.push(trimmed.to_string());
        }
    }
    lines
}

// ─── HTTP Handlers ────────────────────────────────────────

pub fn main() {
    init_log();
    from_feature_flags().install_process_default();

    let certificate = include_bytes!("cer.pem").to_vec();
    let private_key = include_bytes!("key.pem").to_vec();

    let host_addr = util::select_host_address();

    let (tx, rx) = mpsc::sync_channel::<PairedRoom>(4);

    let socket = UdpSocket::bind(format!("{host_addr}:0")).expect("binding a random UDP port");
    let addr = socket.local_addr().expect("a local socket address");
    info!("Bound UDP port: {}", addr);

    let rooms: Rooms = Arc::new(Mutex::new(HashMap::new()));

    thread::spawn(move || run(socket, rx));

    let server = Server::new_ssl(
        "0.0.0.0:3000",
        move |request| web_request(request, addr, tx.clone(), rooms.clone()),
        certificate,
        private_key,
    )
    .expect("starting the web server");

    let port = server.server_addr().port();
    info!(
        "E2EE Tunnel SFU ready at https://{:?}:{}",
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
    // CORS headers for browser clients
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

    // Parse as JSON: {"type":"offer","sdp":"v=0\r\n..."}
    let offer: SdpOffer = match serde_json::from_reader(&mut data) {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to parse SDP offer: {:?}", e);
            return Response::json(&serde_json::json!({"error": format!("bad offer: {e}")}))
                .with_status_code(400);
        }
    };

    // Get the raw SDP string for fingerprint extraction
    let offer_sdp_str = offer.to_sdp_string();
    let fingerprint = match extract_fingerprint(&offer_sdp_str) {
        Some(fp) => fp,
        None => {
            return Response::json(&serde_json::json!({"error": "no fingerprint in offer"}))
                .with_status_code(400);
        }
    };

    info!("Received offer with fingerprint: {}...", &fingerprint[..30.min(fingerprint.len())]);

    let mut rooms_lock = rooms.lock().unwrap();

    // Find a room waiting for a second client, or create a new one
    let waiting_room_id = rooms_lock
        .iter()
        .find(|(_, room)| room.rtc_b.is_none())
        .map(|(id, _)| id.clone());

    if let Some(room_id) = waiting_room_id {
        // Second client joining — pair them!
        info!("Pairing client B into room {}", room_id);

        let room = rooms_lock.get_mut(&room_id).unwrap();
        let fp_a = extract_fingerprint(&room.offer_a_sdp).unwrap();
        let fp_b = fingerprint;

        // Create Rtc for client B
        let mut rtc_b = Rtc::builder()
            .set_tunnel_mode(true)
            .set_rtp_mode(true)
            .set_fingerprint_verification(false)
            .build(Instant::now());

        let candidate = Candidate::host(addr, "udp").expect("a host candidate");
        rtc_b.add_local_candidate(candidate).unwrap();

        let answer_b_raw = match rtc_b.sdp_api().accept_offer(offer) {
            Ok(a) => a,
            Err(e) => {
                error!("Failed to accept offer B: {:?}", e);
                return Response::json(&serde_json::json!({"error": format!("accept failed: {e}")}))
                    .with_status_code(500);
            }
        };

        // Patch answer for B: replace SFU fingerprint with A's, set B as DTLS active (client)
        // Also swap SSRCs: B's answer gets A's SSRCs so B expects A's actual media SSRCs
        let answer_b_sdp = answer_b_raw.to_sdp_string();
        let patched_b = patch_answer_sdp(&answer_b_sdp, &fp_a, "passive", &room.offer_a_sdp);
        let answer_b = SdpAnswer::from_sdp_string(&patched_b).expect("valid patched SDP for B");

        // Patch answer for A: replace SFU fingerprint with B's, set A as DTLS passive (server)
        // Also swap SSRCs: A's answer gets B's SSRCs so A expects B's actual media SSRCs
        let rtc_a = room.rtc_a.take().unwrap();
        let answer_a_raw_sdp = room.answer_a.take().unwrap().to_sdp_string();
        let patched_a = patch_answer_sdp(&answer_a_raw_sdp, &fp_b, "active", &offer_sdp_str);
        let answer_a = SdpAnswer::from_sdp_string(&patched_a).expect("valid patched SDP for A");

        info!(
            "Room {} paired. A fingerprint: {}... B fingerprint: {}...",
            room_id,
            &fp_a[..30.min(fp_a.len())],
            &fp_b[..30.min(fp_b.len())]
        );

        // Store patched answer for A (client A will poll /answer)
        room.answer_a = Some(answer_a);
        room.rtc_b = Some(Rtc::new(Instant::now())); // placeholder — real one sent to run loop

        // Send both Rtc instances to the run loop
        if let Err(e) = tx.send(PairedRoom {
            room_id: room_id.clone(),
            rtc_a,
            rtc_b,
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

        // Create Rtc for client A
        let mut rtc_a = Rtc::builder()
            .set_tunnel_mode(true)
            .set_rtp_mode(true)
            .set_fingerprint_verification(false)
            .build(Instant::now());

        let candidate = Candidate::host(addr, "udp").expect("a host candidate");
        rtc_a.add_local_candidate(candidate).unwrap();

        let answer_a_raw = match rtc_a.sdp_api().accept_offer(offer) {
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
                offer_a_sdp: offer_sdp_str,
                rtc_a: Some(rtc_a),
                answer_a: Some(answer_a_raw),
                rtc_b: None,
            },
        );

        // Return room_id so client A can poll /answer
        Response::json(&serde_json::json!({
            "status": "waiting",
            "room_id": room_id,
            "message": "Waiting for peer. Poll GET /answer?room=<room_id> for your SDP answer."
        }))
    }
}

fn handle_get_answer(request: &Request, rooms: Rooms) -> Response {
    // Extract room_id from query string
    let room_id = request
        .get_param("room")
        .unwrap_or_default();

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
        // Room not yet paired — client A should keep polling
        return Response::json(&serde_json::json!({
            "status": "waiting",
            "message": "Peer has not joined yet."
        }))
        .with_status_code(202);
    }

    // Room is paired — return the patched answer for A
    if let Some(answer) = room.answer_a.take() {
        info!("Returning patched answer for client A in room {}", room_id);
        let body = serde_json::to_vec(&answer).expect("answer to serialize");
        Response::from_data("application/json", body)
    } else {
        // Answer already retrieved
        Response::json(&serde_json::json!({"status": "answered", "message": "Answer already retrieved."}))
    }
}

// ─── Main Run Loop ────────────────────────────────────────

struct TunnelClient {
    id: usize,
    room_id: String,
    role: char, // 'A' or 'B'
    rtc: Rtc,
    ice_connected: bool,
    // Packet counters for debugging
    fwd_dtls: u64,
    fwd_rtp: u64,
    fwd_rtcp: u64,
}

fn run(socket: UdpSocket, rx: Receiver<PairedRoom>) -> ! {
    let mut clients: Vec<TunnelClient> = vec![];
    let mut buf = vec![0; 2000];
    let mut next_id: usize = 0;
    let mut last_stats = Instant::now();

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

            clients.push(TunnelClient {
                id: id_a,
                room_id: paired.room_id.clone(),
                role: 'A',
                rtc: paired.rtc_a,
                ice_connected: false,
                fwd_dtls: 0,
                fwd_rtp: 0,
                fwd_rtcp: 0,
            });
            clients.push(TunnelClient {
                id: id_b,
                room_id: paired.room_id,
                role: 'B',
                rtc: paired.rtc_b,
                ice_connected: false,
                fwd_dtls: 0,
                fwd_rtp: 0,
                fwd_rtcp: 0,
            });
        }

        // Remove dead clients
        clients.retain(|c| c.rtc.is_alive());

        // Process all clients: poll outputs, collect tunnel data to forward
        let mut forwards: Vec<(String, char, Vec<u8>, TunnelPacketType)> = Vec::new();

        for client in clients.iter_mut() {
            loop {
                match client.rtc.poll_output() {
                    Ok(Output::Timeout(_)) => break,
                    Ok(Output::Transmit(t)) => {
                        if let Err(e) = socket.send_to(&t.contents, t.destination) {
                            // TimedOut / ConnectionReset are common on Windows UDP sockets
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
                    Ok(Output::Event(Event::TunnelData(tunnel))) => {
                        let pkt_type_str = match tunnel.pkt_type {
                            TunnelPacketType::Dtls => "DTLS",
                            TunnelPacketType::Rtp => "RTP",
                            TunnelPacketType::Rtcp => "RTCP",
                        };
                        debug!(
                            "Room {} {} → {} ({} bytes, ssrc={:?})",
                            client.room_id,
                            client.role,
                            pkt_type_str,
                            tunnel.data.len(),
                            tunnel.ssrc()
                        );
                        forwards.push((
                            client.room_id.clone(),
                            client.role,
                            tunnel.data,
                            tunnel.pkt_type,
                        ));
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

        // Forward tunnel data: A→B and B→A within same room
        for (room_id, sender_role, data, pkt_type) in forwards {
            let peer_role = if sender_role == 'A' { 'B' } else { 'A' };
            if let Some(peer) = clients
                .iter_mut()
                .find(|c| c.room_id == room_id && c.role == peer_role)
            {
                if peer.ice_connected {
                    match pkt_type {
                        TunnelPacketType::Dtls => peer.fwd_dtls += 1,
                        TunnelPacketType::Rtp => peer.fwd_rtp += 1,
                        TunnelPacketType::Rtcp => peer.fwd_rtcp += 1,
                    }
                    peer.rtc.write_tunnel_data(data);
                } else {
                    debug!(
                        "DROP {}→{}: peer ICE not connected, dropping {:?} ({} bytes)",
                        sender_role, peer_role, pkt_type, data.len()
                    );
                }
            }
        }

        // Periodic stats (every 5 seconds)
        if last_stats.elapsed() > Duration::from_secs(5) {
            for client in clients.iter() {
                if client.fwd_dtls + client.fwd_rtp + client.fwd_rtcp > 0 {
                    info!(
                        "STATS Room {} → {}: forwarded DTLS={} RTP={} RTCP={}",
                        client.room_id,
                        client.role,
                        client.fwd_dtls,
                        client.fwd_rtp,
                        client.fwd_rtcp
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
