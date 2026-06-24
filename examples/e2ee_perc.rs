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
//! ## Signaling Protocol (N:N conference, dynamic)
//!
//! 1. Client:  `POST /offer` with `{type, sdp, room, name}` → `{type, sdp, client_id}`
//!    The `room` field is the conference id; clients sharing a `room` see each
//!    other. Each client does its own DTLS-SRTP with the SFU (no pairing), and
//!    the answer (plus an assigned `client_id`) is returned immediately.
//! 2. Client:  `GET /signal?client_id=N` → `{reoffer, recv_slots}`
//!    Polled by each client. `recv_slots` is how many receive m-lines per media
//!    kind it should offer (one per *other* participant). When this exceeds what
//!    it currently has, the client adds `recvonly` transceivers and re-offers.
//! 3. Client:  `POST /offer` with `{..., client_id}` → renegotiation. The SFU
//!    accepts the re-offer on the existing `Rtc`, growing its receive-slot pool.
//!
//! The conference grows and shrinks dynamically — there is no fixed slot pool
//! and no participant cap. A 2-party call needs no renegotiation at all.
//!
//! ## Usage
//!
//! ```text
//! cargo run --example e2ee_perc --no-default-features --features "wincrypto,examples"
//! ```

#[macro_use]
extern crate tracing;

use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rouille::Server;
use rouille::{Request, Response};
use str0m::change::SdpOffer;
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

// ─── Conference State ──────────────────────────────────────
//
// N:N model: clients are grouped into conferences by `conf_id`. Each client
// has its own independent DTLS-SRTP session with the SFU (rtp_mode) — there is
// no DTLS tunnel and no client pairing. The SFU fans out every sender's RTP to
// all OTHER clients in the same conference. The inner E2E encrypted payload
// passes through opaquely; the SFU never decrypts it.

/// A signaling request handed from the web thread to the run loop. It carries
/// either a fresh join (`client_id == None`) or a renegotiation from an
/// already-connected client (`client_id == Some(id)`), which adds receive
/// slots so the conference can grow dynamically. The run loop owns every `Rtc`,
/// so all SDP work (accept_offer for both join and renegotiation) happens there
/// and the resulting answer is sent back over `reply`.
struct OfferRequest {
    /// `None` for an initial join; `Some(id)` for a renegotiation re-offer.
    client_id: Option<usize>,
    conf_id: String,
    name: String,
    sdp: String,
    reply: SyncSender<OfferReply>,
}

/// The run loop's response to an [`OfferRequest`], returned to the HTTP client.
struct OfferReply {
    ok: bool,
    /// The id assigned to (or matched for) this client.
    client_id: usize,
    /// The SDP answer string the client sets as its remote description.
    answer_sdp: String,
    error: Option<String>,
}

/// Per-client renegotiation instructions, shared between the web thread (which
/// serves them over `GET /signal`) and the run loop (which recomputes them when
/// conference membership changes). Maps `client id → desired receive slots per
/// media kind`. A client that has fewer receive m-lines than this re-offers to
/// add the difference; once satisfied the instruction is a harmless no-op.
type ReofferState = Arc<Mutex<HashMap<usize, usize>>>;

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

    let (tx, rx) = mpsc::sync_channel::<OfferRequest>(8);
    let reoffer: ReofferState = Arc::new(Mutex::new(HashMap::new()));

    // UDP bind: config udpHost (default to discovered host) + udpPort (0=random).
    let udp_host = util::cfg_str(&cfg, "udpHost", &host_addr.to_string());
    let udp_port = util::cfg_u64(&cfg, "udpPort", 0);
    let socket =
        UdpSocket::bind(format!("{udp_host}:{udp_port}")).expect("binding the UDP port");
    let addr = socket.local_addr().expect("a local socket address");
    info!("Bound UDP port: {}", addr);

    let stats_interval = util::cfg_u64(&cfg, "statsIntervalSec", 5);
    let wire_log = util::cfg_bool(&cfg, "diagnostics.wireLog", true);
    let reoffer_run = reoffer.clone();
    thread::spawn(move || run(socket, rx, reoffer_run, stats_interval, wire_log));

    let http_host = util::cfg_str(&cfg, "httpHost", "0.0.0.0");
    let http_port = util::cfg_u64(&cfg, "httpPort", 3000);
    let server = Server::new_ssl(
        format!("{http_host}:{http_port}"),
        move |request| web_request(request, tx.clone(), reoffer.clone()),
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
    info!("  POST /offer            — submit SDP offer (JSON: {{type, sdp, room, name, client_id?}})");
    info!("  GET  /signal?client_id — poll for renegotiation instructions");

    server.run();
}

fn web_request(
    request: &Request,
    tx: SyncSender<OfferRequest>,
    reoffer: ReofferState,
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
        ("POST", "/offer") => handle_offer(request, &tx),
        ("GET", url) if url.starts_with("/signal") => handle_signal(request, &reoffer),
        ("GET", url) if url.starts_with("/answer") => handle_get_answer(request),
        _ => Response::json(&serde_json::json!({"error": "not found"})).with_status_code(404),
    };

    for (k, v) in cors {
        resp = resp.with_additional_header(k, v);
    }
    resp
}

fn handle_offer(request: &Request, tx: &SyncSender<OfferRequest>) -> Response {
    let Some(mut data) = request.data() else {
        return Response::json(&serde_json::json!({"error": "no body"})).with_status_code(400);
    };

    // Body: { type, sdp, room?, name?, client_id? }
    // `room` groups clients into a conference; `name` is a human label for logs.
    // `client_id` is present only on renegotiation re-offers (the SFU assigns it
    // in the answer to the initial offer); its absence means a fresh join.
    let body: serde_json::Value = match serde_json::from_reader(&mut data) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to parse offer body: {:?}", e);
            return Response::json(&serde_json::json!({"error": format!("bad body: {e}")}))
                .with_status_code(400);
        }
    };

    let sdp = body.get("sdp").and_then(|v| v.as_str()).unwrap_or_default();
    if sdp.is_empty() {
        return Response::json(&serde_json::json!({"error": "missing sdp"}))
            .with_status_code(400);
    }
    let conf_id = body
        .get("room")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("default")
        .to_string();
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("?")
        .to_string();
    let client_id = body
        .get("client_id")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);

    // Forward the offer to the run loop (which owns every Rtc) and wait for the
    // answer. A bounded reply channel keeps this request/response synchronous.
    let (reply_tx, reply_rx) = mpsc::sync_channel::<OfferReply>(1);
    if tx
        .send(OfferRequest {
            client_id,
            conf_id,
            name,
            sdp: sdp.to_string(),
            reply: reply_tx,
        })
        .is_err()
    {
        return Response::json(&serde_json::json!({"error": "server busy"}))
            .with_status_code(503);
    }

    match reply_rx.recv() {
        Ok(reply) if reply.ok => Response::json(&serde_json::json!({
            "type": "answer",
            "sdp": reply.answer_sdp,
            "client_id": reply.client_id,
        })),
        Ok(reply) => Response::json(
            &serde_json::json!({"error": reply.error.unwrap_or_else(|| "offer failed".into())}),
        )
        .with_status_code(500),
        Err(_) => Response::json(&serde_json::json!({"error": "run loop gone"}))
            .with_status_code(500),
    }
}

/// Renegotiation poll. A client asks how many receive slots it should offer per
/// media kind; when that exceeds what it currently has, it re-offers to add the
/// difference. This is what lets a conference grow without a fixed slot pool.
fn handle_signal(request: &Request, reoffer: &ReofferState) -> Response {
    let Some(id) = request
        .get_param("client_id")
        .and_then(|s| s.parse::<usize>().ok())
    else {
        return Response::json(&serde_json::json!({"error": "missing client_id"}))
            .with_status_code(400);
    };
    let desired = reoffer.lock().unwrap().get(&id).copied().unwrap_or(0);
    Response::json(&serde_json::json!({
        "reoffer": desired > 0,
        "recv_slots": desired,
    }))
}

/// Legacy endpoint kept for backwards compatibility with old polling clients.
fn handle_get_answer(_request: &Request) -> Response {
    Response::json(&serde_json::json!({
        "status": "answered",
        "message": "Answer is returned directly by POST /offer."
    }))
}

// ─── Main Run Loop ────────────────────────────────────────

struct PercClient {
    id: usize,
    conf_id: String,
    name: String,
    rtc: Rtc,
    ice_connected: bool,
    dtls_connected: bool,
    /// Media lines from this client's SDP (mid, kind). Starts as the client's
    /// own sendrecv audio+video and grows on renegotiation as the SFU-driven
    /// `recvonly` slots are added. Every mid here is writable by the SFU and
    /// forms this client's pool of receive slots.
    media: Vec<(Mid, MediaKind)>,
    /// SSRC → media kind mapping, learned from incoming RTP packets
    rx_ssrc_kind: HashMap<Ssrc, MediaKind>,
    /// Receive-slot assignment: (origin client id, kind) → local tx mid. The
    /// SFU pins each remote participant to a distinct local m-line so this
    /// client renders one window per participant.
    slot_for_origin: HashMap<(usize, MediaKind), Mid>,
    // Forwarding stats
    fwd_rtp: u64,
}

/// Allocate (or look up) the receive slot on `receiver` that carries media of
/// `kind` originating from client `origin`. Returns `None` if the receiver has
/// no free m-line of that kind left (conference larger than its slot pool).
fn assign_slot(receiver: &mut PercClient, origin: usize, kind: MediaKind) -> Option<Mid> {
    if let Some(mid) = receiver.slot_for_origin.get(&(origin, kind)) {
        return Some(*mid);
    }
    let used: HashSet<Mid> = receiver
        .slot_for_origin
        .iter()
        .filter(|((_, k), _)| *k == kind)
        .map(|(_, m)| *m)
        .collect();
    let free = receiver
        .media
        .iter()
        .filter(|(_, k)| *k == kind)
        .map(|(m, _)| *m)
        .find(|m| !used.contains(m));
    if let Some(mid) = free {
        receiver.slot_for_origin.insert((origin, kind), mid);
        info!(
            "Conference '{}': client '{}' slot {} → participant #{} {:?}",
            receiver.conf_id, receiver.name, mid, origin, kind
        );
        Some(mid)
    } else {
        None
    }
}

/// Recompute, for every participant in `conf_id`, how many receive slots per
/// media kind it should offer: one per *other* participant. Stored in the shared
/// [`ReofferState`] so the web thread can hand it out over `GET /signal`. Clients
/// top up to this number by renegotiating; if they already meet it, it's a no-op.
fn update_reoffer(clients: &[PercClient], reoffer: &ReofferState, conf_id: &str) {
    let n = clients.iter().filter(|c| c.conf_id == conf_id).count();
    let desired = n.saturating_sub(1);
    let mut map = reoffer.lock().unwrap();
    for c in clients.iter().filter(|c| c.conf_id == conf_id) {
        map.insert(c.id, desired);
    }
}

/// An RTP packet to fan out from its origin client to every other participant.
struct ForwardPacket {
    conf_id: String,
    origin_id: usize,
    media_kind: MediaKind,
    // RTP header fields (from sender)
    pt: Pt,
    seq_no: SeqNo,
    timestamp: u32,
    marker: bool,
    ext_vals: ExtensionValues,
    /// The RTP payload — contains the inner E2E ciphertext (opaque to the SFU).
    payload: Vec<u8>,
}

/// A keyframe (PLI/FIR) request to relay back to a specific origin sender.
struct KeyframeReq {
    conf_id: String,
    /// The origin participant the requester is missing a keyframe for, resolved
    /// from the requester's slot assignment. `None` → broadcast to all senders.
    target_origin: Option<usize>,
    kind: KeyframeRequestKind,
}

fn run(
    socket: UdpSocket,
    rx: Receiver<OfferRequest>,
    reoffer: ReofferState,
    stats_interval: u64,
    wire_log: bool,
) -> ! {
    let mut clients: Vec<PercClient> = vec![];
    let mut buf = vec![0; 2000];
    let mut next_id: usize = 0;
    let mut last_stats = Instant::now();
    let local_addr = socket.local_addr().expect("a local socket address");
    // DIAG: track distinct (ssrc, pt) seen on the wire to confirm what media
    // actually arrives at the SFU, independent of str0m's SSRC discovery.
    let mut seen_wire: std::collections::HashSet<(u32, u8)> = std::collections::HashSet::new();

    loop {
        // Accept joins and renegotiation re-offers. The run loop owns every Rtc,
        // so all accept_offer work (initial and renegotiation) happens here.
        while let Ok(req) = rx.try_recv() {
            let offer = match SdpOffer::from_sdp_string(&req.sdp) {
                Ok(o) => o,
                Err(e) => {
                    error!("Failed to parse SDP offer: {:?}", e);
                    let _ = req.reply.send(OfferReply {
                        ok: false,
                        client_id: 0,
                        answer_sdp: String::new(),
                        error: Some(format!("bad offer: {e}")),
                    });
                    continue;
                }
            };
            let media = extract_media_info(&req.sdp);

            match req.client_id {
                // Fresh join: build a new Rtc and answer.
                None => {
                    let id = next_id;
                    next_id += 1;

                    let mut rtc = Rtc::builder().set_rtp_mode(true).build(Instant::now());
                    let candidate = Candidate::host(local_addr, "udp").expect("a host candidate");
                    rtc.add_local_candidate(candidate).unwrap();

                    let answer = match rtc.sdp_api().accept_offer(offer) {
                        Ok(a) => a,
                        Err(e) => {
                            error!("Failed to accept offer for '{}': {:?}", req.name, e);
                            let _ = req.reply.send(OfferReply {
                                ok: false,
                                client_id: 0,
                                answer_sdp: String::new(),
                                error: Some(format!("accept failed: {e}")),
                            });
                            continue;
                        }
                    };

                    let n_in_conf =
                        clients.iter().filter(|c| c.conf_id == req.conf_id).count() + 1;
                    info!(
                        "Conference '{}': participant #{} '{}' active ({} in conference, {} media lines)",
                        req.conf_id, id, req.name, n_in_conf, media.len()
                    );

                    clients.push(PercClient {
                        id,
                        conf_id: req.conf_id.clone(),
                        name: req.name.clone(),
                        rtc,
                        ice_connected: false,
                        dtls_connected: false,
                        media,
                        rx_ssrc_kind: HashMap::new(),
                        slot_for_origin: HashMap::new(),
                        fwd_rtp: 0,
                    });

                    // Membership changed — recompute how many receive slots each
                    // participant should offer, so they all renegotiate to fit.
                    update_reoffer(&clients, &reoffer, &req.conf_id);

                    let _ = req.reply.send(OfferReply {
                        ok: true,
                        client_id: id,
                        answer_sdp: answer.to_sdp_string(),
                        error: None,
                    });
                }
                // Renegotiation: accept the re-offer on the existing Rtc and grow
                // this client's receive-slot pool.
                Some(id) => {
                    let Some(client) = clients.iter_mut().find(|c| c.id == id) else {
                        let _ = req.reply.send(OfferReply {
                            ok: false,
                            client_id: id,
                            answer_sdp: String::new(),
                            error: Some("unknown client_id".into()),
                        });
                        continue;
                    };
                    match client.rtc.sdp_api().accept_offer(offer) {
                        Ok(answer) => {
                            client.media = media;
                            info!(
                                "Conference '{}': client '{}' renegotiated ({} media lines)",
                                client.conf_id,
                                client.name,
                                client.media.len()
                            );
                            let _ = req.reply.send(OfferReply {
                                ok: true,
                                client_id: id,
                                answer_sdp: answer.to_sdp_string(),
                                error: None,
                            });
                        }
                        Err(e) => {
                            error!("Renegotiation accept failed for '{}': {:?}", client.name, e);
                            let _ = req.reply.send(OfferReply {
                                ok: false,
                                client_id: id,
                                answer_sdp: String::new(),
                                error: Some(format!("renegotiation failed: {e}")),
                            });
                        }
                    }
                }
            }
        }

        // Remove dead clients. If anyone left, recompute receive-slot targets for
        // the affected conferences so the remaining participants' counts stay
        // correct (departed slots simply go idle until reused).
        let before: Vec<(usize, String)> =
            clients.iter().map(|c| (c.id, c.conf_id.clone())).collect();
        clients.retain(|c| c.rtc.is_alive());
        if clients.len() != before.len() {
            let gone_confs: HashSet<String> = before
                .iter()
                .filter(|(id, _)| !clients.iter().any(|c| c.id == *id))
                .map(|(_, conf)| conf.clone())
                .collect();
            for conf in &gone_confs {
                update_reoffer(&clients, &reoffer, conf);
            }
        }

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
                            "Conf '{}' #{} '{}': ICE {:?}",
                            client.conf_id, client.id, client.name, state
                        );
                        client.ice_connected = matches!(
                            state,
                            IceConnectionState::Connected | IceConnectionState::Completed
                        );
                    }
                    Ok(Output::Event(Event::Connected)) => {
                        info!(
                            "Conf '{}' #{} '{}': DTLS connected",
                            client.conf_id, client.id, client.name
                        );
                        client.dtls_connected = true;
                    }
                    Ok(Output::Event(Event::MediaAdded(media_added))) => {
                        info!(
                            "Conf '{}' #{} '{}': media added mid={} kind={:?} dir={:?}",
                            client.conf_id,
                            client.id,
                            client.name,
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
                                "Conf '{}' #{} '{}': learned SSRC {} → {:?}",
                                client.conf_id, client.id, client.name, ssrc, kind
                            );
                            kind
                        } else {
                            *client.rx_ssrc_kind.get(&ssrc).unwrap()
                        };

                        debug!(
                            "Conf '{}' '{}' → {:?} RTP seq={} ts={} pt={} marker={} payload={} bytes",
                            client.conf_id,
                            client.name,
                            kind,
                            pkt.header.sequence_number,
                            pkt.header.timestamp,
                            pkt.header.payload_type,
                            pkt.header.marker,
                            pkt.payload.len(),
                        );

                        forwards.push(ForwardPacket {
                            conf_id: client.conf_id.clone(),
                            origin_id: client.id,
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
                            "Conf '{}' #{} '{}': keyframe request {:?}",
                            client.conf_id, client.id, client.name, req
                        );
                        // The request arrives on a receive slot (req.mid). Map
                        // that slot back to the participant whose video it
                        // carries, so we relay the keyframe request to that
                        // exact sender. If the slot isn't assigned yet, fall
                        // back to broadcasting to all senders in the conference.
                        let target_origin = client
                            .slot_for_origin
                            .iter()
                            .find(|((_, k), m)| *k == MediaKind::Video && **m == req.mid)
                            .map(|((o, _), _)| *o);
                        keyframe_reqs.push(KeyframeReq {
                            conf_id: client.conf_id.clone(),
                            target_origin,
                            kind: req.kind,
                        });
                    }
                    Ok(Output::Event(e)) => {
                        debug!(
                            "Conf '{}' #{} '{}': {:?}",
                            client.conf_id, client.id, client.name, e
                        );
                    }
                    Err(e) => {
                        error!(
                            "Conf '{}' #{} '{}': error {:?}",
                            client.conf_id, client.id, client.name, e
                        );
                        client.rtc.disconnect();
                        break;
                    }
                }
            }
        }

        // Fan out each RTP packet to every OTHER participant in its conference.
        for fwd in forwards {
            let receiver_idxs: Vec<usize> = clients
                .iter()
                .enumerate()
                .filter(|(_, c)| {
                    c.conf_id == fwd.conf_id && c.id != fwd.origin_id && c.dtls_connected
                })
                .map(|(i, _)| i)
                .collect();

            for ri in receiver_idxs {
                let receiver = &mut clients[ri];

                // Pin this origin to one of the receiver's local m-lines so each
                // participant lands on a distinct receive slot (one window each).
                let Some(mid) = assign_slot(receiver, fwd.origin_id, fwd.media_kind) else {
                    debug!(
                        "Conf '{}' '{}': no free {:?} slot for participant #{}",
                        receiver.conf_id, receiver.name, fwd.media_kind, fwd.origin_id
                    );
                    continue;
                };

                // The payload is opaque E2E ciphertext produced by the sender's
                // frame-level transform (encryption happens on the whole encoded
                // frame, before RTP packetization). Because the SFU forwards at
                // the RTP-packet level, a single encoded frame may span many
                // packets. We MUST NOT inject any per-packet bytes (e.g. an OHB)
                // here: doing so would corrupt the reassembled ciphertext and
                // break GCM auth for any multi-packet frame. Forward verbatim.
                let mut direct = receiver.rtc.direct_api();
                if let Some(stream) = direct.stream_tx_by_mid(mid, None) {
                    match stream.write_rtp(
                        fwd.pt,
                        fwd.seq_no,
                        fwd.timestamp,
                        Instant::now(),
                        fwd.marker,
                        fwd.ext_vals.clone(),
                        true, // nackable — video packets should be nackable
                        fwd.payload.clone(),
                    ) {
                        Ok(_) => {
                            drop(direct);
                            receiver.fwd_rtp += 1;
                        }
                        Err(e) => {
                            debug!("write_rtp error for '{}': {:?}", receiver.name, e);
                        }
                    }
                } else {
                    debug!(
                        "No tx stream for mid={} on '{}' (conf '{}')",
                        mid, receiver.name, fwd.conf_id
                    );
                }
            }
        }

        // Relay keyframe requests (PLI/FIR) to the participant whose video the
        // requesting receiver is missing a keyframe for. A receiver that joins
        // mid-stream needs a keyframe to start decoding; without this relay its
        // PLIs are dropped and the sender never refreshes.
        for kreq in keyframe_reqs {
            let sender_idxs: Vec<usize> = clients
                .iter()
                .enumerate()
                .filter(|(_, c)| {
                    c.conf_id == kreq.conf_id
                        && match kreq.target_origin {
                            Some(o) => c.id == o,
                            None => true, // broadcast fallback
                        }
                })
                .map(|(i, _)| i)
                .collect();

            for si in sender_idxs {
                let sender = &mut clients[si];
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
                            "Conf '{}' relayed keyframe request {:?} to '{}' ssrc={}",
                            kreq.conf_id, kreq.kind, sender.name, ssrc
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
                        "STATS Conf '{}' → '{}': forwarded RTP={}",
                        client.conf_id, client.name, client.fwd_rtp,
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
