#![allow(dead_code)] // not every parsed header field is displayed yet

use std::{
    cell::RefCell,
    clone, fmt,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use pcap::{Capture, Device, Linktype};
use ratatui::{
    Frame,
    crossterm::event::{KeyCode, KeyEvent},
    layout::{self, Constraint, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
        ScrollbarState,
    },
};

use crate::{
    app::App,
    events::{Event, EventSender},
    traits::AppMod,
};

// ───────────────────────────── Events & errors ─────────────────────────────

#[derive(Debug)]
pub enum SnifferEvent {
    Packet(Arc<Packet>),
    Stopped,
}

#[derive(Debug)]
pub enum ParseError {
    MalformedPacket,
}

// ───────────────────────────── Packet model ─────────────────────────────

#[derive(Debug)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

impl EthernetHeader {
    pub fn ether_type_str(&self) -> String {
        match self.ether_type {
            0x0800 => "IPv4".to_string(),
            0x86DD => "IPv6".to_string(),
            0x0806 => "ARP".to_string(),
            other => format!("Unknown (0x{other:04X})"),
        }
    }
}

#[derive(Debug)]
pub struct IPv4Header {
    pub version: u8,
    pub ihl: u8,

    pub dscp: u8,
    pub ecn: u8,

    pub total_length: u16,
    pub identification: u16,

    pub reserved: u8,
    pub dont_fragment: u8,
    pub more_fragments: u8,

    pub fragment_offset: u16,

    pub ttl: u8,
    pub protocol: u8,

    pub checksum: u16,

    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

impl fmt::Display for IPv4Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPv4 {{
  version: {},
  ihl: {},
  dscp: {},
  ecn: {},
  total_length: {},
  identification: {},
  flags: R:{} DF:{} MF:{},
  fragment_offset: {},
  ttl: {},
  protocol: {},
  checksum: 0x{:04X},
  src: {},
  dst: {}
}}",
            self.version,
            self.ihl,
            self.dscp,
            self.ecn,
            self.total_length,
            self.identification,
            self.reserved,
            self.dont_fragment,
            self.more_fragments,
            self.fragment_offset,
            self.ttl,
            self.protocol,
            self.checksum,
            self.src,
            self.dst,
        )
    }
}

#[derive(Debug)]
pub struct IPv6Header {
    pub version: u8,

    pub traffic_class: u8,
    pub flow_label: u32,

    pub payload_length: u16,

    pub next_header: u8,
    pub hop_limit: u8,

    pub src: [u8; 16],
    pub dst: [u8; 16],
}

#[derive(Debug)]
pub struct ArpHeader {
    pub hardware_type: u16,
    pub protocol_type: u16,

    pub hardware_len: u8,
    pub protocol_len: u8,

    pub operation: u16,

    pub sender_hardware_addr: Vec<u8>,
    pub sender_protocol_addr: Vec<u8>,

    pub target_hardware_addr: Vec<u8>,
    pub target_protocol_addr: Vec<u8>,
}

#[derive(Debug)]
pub enum NetworkLayer {
    IPv4(IPv4Header),
    IPv6(IPv6Header),
    Arp(ArpHeader),
}

#[derive(Debug)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,

    pub seq: u32,
    pub ack: u32,

    pub data_offset: u8,

    pub flags: TcpFlags,

    pub window_size: u16,

    pub checksum: u16,
    pub urgent_pointer: u16,

    pub options: Vec<TcpOption>,
}

#[derive(Debug, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    /// Comma separated names of the set flags, e.g. "SYN,ACK".
    pub fn names(&self) -> String {
        let all = [
            (self.syn, "SYN"),
            (self.ack, "ACK"),
            (self.fin, "FIN"),
            (self.rst, "RST"),
            (self.psh, "PSH"),
            (self.urg, "URG"),
            (self.ece, "ECE"),
            (self.cwr, "CWR"),
        ];
        let names: Vec<&str> = all
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, name)| *name)
            .collect();

        if names.is_empty() {
            "-".to_string()
        } else {
            names.join(",")
        }
    }
}

#[derive(Debug)]
pub enum TcpOption {
    End,
    NoOperation,
    MaximumSegmentSize { value: u16 },
    WindowScale { shift: u8 },
    SackPermitted,
    Timestamp { ts_value: u32, ts_echo: u32 },
    Unknown { kind: u8, data: Vec<u8> },
}

#[derive(Debug)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,

    pub length: u16,
    pub checksum: u16,
}

#[derive(Debug)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,

    pub checksum: u16,
}

#[derive(Debug)]
pub struct Icmpv6Header {
    pub icmp_type: u8,
    pub code: u8,

    pub checksum: u16,
}

#[derive(Debug)]
pub enum TransportLayer {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Icmp(IcmpHeader),
    Icmpv6(Icmpv6Header),
}

#[derive(Debug)]
pub struct Packet {
    pub ethernet: EthernetHeader,
    pub network: Option<NetworkLayer>,
    pub transport: Option<TransportLayer>,
    pub payload: Vec<u8>,
}

// ───────────────────────────── Module state ─────────────────────────────

pub struct SnifferModState {
    packets: Vec<Arc<Packet>>,
    selected_packet: usize,
    inspected_packet: Option<Arc<Packet>>,
    list_state: RefCell<ListState>,
    is_running: bool,
    max_packets: usize,
    auto_scroll: bool,
    /// Set to true to get the sniffer thread to stop.
    stop: Arc<AtomicBool>,
}

pub struct SnifferMod {
    state: SnifferModState,
}

impl Default for SnifferMod {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SnifferMod {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::Relaxed);
    }
}

impl SnifferMod {
    pub fn new() -> Self {
        let max_packets = 1000;
        let state = SnifferModState {
            packets: Vec::with_capacity(max_packets),
            selected_packet: 0,
            inspected_packet: None,
            list_state: RefCell::new(ListState::default()),
            is_running: false,
            max_packets,
            auto_scroll: true,
            stop: Arc::new(AtomicBool::new(false)),
        };
        Self { state }
    }

    fn push_packet(&mut self, packet: Arc<Packet>) {
        let st = &mut self.state;
        if st.packets.len() >= st.max_packets {
            return;
        }
        st.packets.push(packet);
        if st.auto_scroll {
            st.selected_packet = st.packets.len() - 1;
        }
    }

    pub fn start(&mut self, sender: &EventSender) {
        if self.state.is_running {
            return;
        }
        self.state.is_running = true;

        let stop = Arc::new(AtomicBool::new(false));
        self.state.stop = stop.clone();
        let sender = sender.clone();

        std::thread::spawn(move || {
            if let Err(msg) = background_sniffing(&sender, &stop) {
                sender.blocking_send_core(Event::Popup(msg));
            }
            sender.blocking_send(SnifferEvent::Stopped);
        });
    }

    pub fn stop(&mut self) {
        self.state.stop.store(true, Ordering::Relaxed);
    }

    fn select_next(&mut self) {
        let st = &mut self.state;
        if st.packets.is_empty() {
            return;
        }
        let last = st.packets.len() - 1;
        if st.selected_packet < last {
            st.selected_packet += 1;
        }
        // reaching the bottom re-enables following new packets
        if st.selected_packet >= last {
            st.auto_scroll = true;
        }
    }

    fn select_prev(&mut self) {
        let st = &mut self.state;
        if st.selected_packet > 0 {
            st.selected_packet -= 1;
            // moving up pauses following new packets
            st.auto_scroll = false;
        }
    }

    fn render_packets(&self, f: &mut Frame, area: Rect) {
        let st = &self.state;

        let status = if st.is_running { "CAPTURING" } else { "IDLE" };
        let auto = if st.auto_scroll { "ON" } else { "OFF" };
        let full = if st.packets.len() >= st.max_packets {
            " | BUFFER FULL [c: clear]"
        } else {
            ""
        };
        let title = format!(
            " [ SNIFFER: {status} | {}/{} packets | auto-scroll {auto}{full} ] ",
            st.packets.len(),
            st.max_packets
        );
        let color = if st.is_running {
            Color::Green
        } else {
            Color::Cyan
        };

        let block = Block::bordered()
            .title(title)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(color));
        let inner = block.inner(area);
        f.render_widget(block, area);

        if st.packets.is_empty() {
            let hint = if st.is_running {
                "Waiting for packets..."
            } else {
                "Press [s] to start capturing"
            };
            f.render_widget(
                Paragraph::new(hint).style(Style::default().fg(Color::DarkGray)),
                inner,
            );
            return;
        }

        let separator = "─".repeat(inner.width.saturating_sub(4) as usize);
        let items: Vec<ListItem> = st
            .packets
            .iter()
            .enumerate()
            .map(|(i, p)| packet_to_item(i, p, &separator))
            .collect();

        let list = List::new(items)
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");

        let selected = st.selected_packet.min(st.packets.len() - 1);

        let mut list_state = st.list_state.borrow_mut();
        list_state.select(Some(selected));
        f.render_stateful_widget(list, inner, &mut *list_state);

        let mut scrollbar_state = ScrollbarState::new(st.packets.len()).position(selected);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("▲"))
            .end_symbol(Some("▼"))
            .track_symbol(Some("│"))
            .thumb_symbol("█");

        f.render_stateful_widget(
            scrollbar,
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }

    fn render_packet_inspection(&self, f: &mut Frame, area: Rect, packet: &Packet) {
        let paragraph = Paragraph::new(format!("{:?}", packet));

        f.render_widget(
            paragraph,
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
        );
    }
}

// ───────────────────────────── AppMod ─────────────────────────────

impl AppMod for SnifferMod {
    fn update(&mut self, event: &Event, _tx: &EventSender) {
        let Some(ev) = event.downcast_ref::<SnifferEvent>() else {
            return;
        };

        match ev {
            SnifferEvent::Packet(packet) => self.push_packet(packet.clone()),
            SnifferEvent::Stopped => self.state.is_running = false,
        }
    }

    fn on_key(&mut self, key: &KeyEvent, sender: &EventSender) {
        match key.code {
            KeyCode::Char('s') => self.start(sender),
            KeyCode::Char('d') => self.stop(),
            KeyCode::Char('c') => {
                self.state.packets.clear();
                self.state.selected_packet = 0;
            }
            KeyCode::Char('a') => {
                self.state.auto_scroll = !self.state.auto_scroll;
                if self.state.auto_scroll {
                    self.state.selected_packet = self.state.packets.len().saturating_sub(1);
                }
            }

            // PACKET LIST CONTROLS
            KeyCode::Down | KeyCode::Char('j') => self.select_next(),
            KeyCode::Up | KeyCode::Char('k') => self.select_prev(),
            KeyCode::Home => {
                self.state.selected_packet = 0;
                self.state.auto_scroll = false;
            }
            KeyCode::End => {
                self.state.selected_packet = self.state.packets.len().saturating_sub(1);
                self.state.auto_scroll = true;
            }

            // Packet INSPECTION
            KeyCode::Enter => {
                if let Some(p) = self.state.packets.get(self.state.selected_packet) {
                    self.state.inspected_packet = Some(Arc::clone(p));
                };
            }

            KeyCode::Esc => {
                self.state.inspected_packet = None;
            }
            _ => {}
        }
    }

    fn render(&self, f: &mut Frame, area: Rect, _app: &App) {
        let st = &self.state;

        if let Some(p) = st.inspected_packet.clone() {
            let layout = Layout::default()
                .constraints(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
                .direction(layout::Direction::Vertical)
                .split(area);

            self.render_packets(f, layout[0]);
            self.render_packet_inspection(f, layout[1], &p);
        } else {
            self.render_packets(f, area);
        }
    }

    fn captures_input(&self) -> bool {
        false
    }

    fn instructions(&self) -> Vec<String> {
        vec![
            "[s: Start]".to_string(),
            "[d: Stop]".to_string(),
            "[c: Clear]".to_string(),
            "[a: Auto-scroll]".to_string(),
            "[j/k: Move]".to_string(),
        ]
    }
}

// ───────────────────────────── Rendering helpers ─────────────────────────────

fn packet_to_item(index: usize, p: &Packet, separator: &str) -> ListItem<'static> {
    let dim = Style::default().fg(Color::DarkGray);

    let src = bytes_to_hex(&p.ethernet.src_mac, ":");
    let dst = bytes_to_hex(&p.ethernet.dst_mac, ":");

    let mut lines = vec![Line::from(vec![
        Span::raw(format!("[{index}] ")),
        Span::styled("ETH ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(format!("{src} → {dst}  ")),
        Span::styled(
            p.ethernet.ether_type_str(),
            Style::default().fg(Color::Cyan),
        ),
    ])];

    if let Some(net) = &p.network {
        lines.push(Line::from(vec![
            Span::raw("    net: "),
            Span::raw(network_summary(net)),
        ]));
    }

    if let Some(transport) = &p.transport {
        lines.push(Line::from(vec![
            Span::raw("    trn: "),
            Span::styled(
                transport_summary(transport),
                Style::default().fg(Color::Blue),
            ),
        ]));
    }

    if !p.payload.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("    payload: {} bytes", p.payload.len()),
            dim,
        )));
    }

    lines.push(Line::from(Span::styled(separator.to_string(), dim)));

    ListItem::new(lines)
}

fn protocol_name(protocol: u8) -> String {
    match protocol {
        1 => "ICMP".to_string(),
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        58 => "ICMPv6".to_string(),
        other => other.to_string(),
    }
}

fn network_summary(net: &NetworkLayer) -> String {
    match net {
        NetworkLayer::IPv4(h) => format!(
            "IPv4 {} → {}  ttl={} proto={} len={}",
            h.src,
            h.dst,
            h.ttl,
            protocol_name(h.protocol),
            h.total_length
        ),
        NetworkLayer::IPv6(h) => format!(
            "IPv6 {} → {}  hop={} next={} len={}",
            Ipv6Addr::from(h.src),
            Ipv6Addr::from(h.dst),
            h.hop_limit,
            protocol_name(h.next_header),
            h.payload_length
        ),
        NetworkLayer::Arp(a) => arp_summary(a),
    }
}

fn arp_summary(a: &ArpHeader) -> String {
    let op = match a.operation {
        1 => "request",
        2 => "reply",
        _ => "other",
    };

    let ipv4 = |b: &[u8]| Ipv4Addr::new(b[0], b[1], b[2], b[3]);

    if a.protocol_type == 0x0800
        && a.sender_protocol_addr.len() == 4
        && a.target_protocol_addr.len() == 4
    {
        format!(
            "ARP {op}: {} → {}",
            ipv4(&a.sender_protocol_addr),
            ipv4(&a.target_protocol_addr)
        )
    } else {
        format!(
            "ARP {op} (hw_len={}, proto_len={})",
            a.hardware_len, a.protocol_len
        )
    }
}

fn transport_summary(t: &TransportLayer) -> String {
    match t {
        TransportLayer::Tcp(h) => format!(
            "TCP {} → {}  [{}] seq={} ack={} win={}",
            h.src_port,
            h.dst_port,
            h.flags.names(),
            h.seq,
            h.ack,
            h.window_size
        ),
        TransportLayer::Udp(h) => {
            format!("UDP {} → {}  len={}", h.src_port, h.dst_port, h.length)
        }
        TransportLayer::Icmp(h) => format!("ICMP type={} code={}", h.icmp_type, h.code),
        TransportLayer::Icmpv6(h) => format!("ICMPv6 type={} code={}", h.icmp_type, h.code),
    }
}

// ───────────────────────────── Capture thread ─────────────────────────────

fn background_sniffing(sender: &EventSender, stop: &AtomicBool) -> Result<(), String> {
    let device = Device::lookup()
        .map_err(|e| format!("Failed to look up a network interface: {e}"))?
        .ok_or_else(|| "No default network interface found.".to_string())?;

    let mut cap = Capture::from_device(device)
        .and_then(|c| {
            c.promisc(true)
                .snaplen(65535)
                .immediate_mode(true)
                .timeout(100)
                .open()
        })
        .map_err(|e| {
            format!("Failed to open capture device: {e}\n(root or CAP_NET_RAW is required)")
        })?;

    if cap.get_datalink() != Linktype::ETHERNET {
        return Err(format!(
            "Unsupported link type {:?}: only Ethernet is supported.",
            cap.get_datalink()
        ));
    }

    while !stop.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(raw) => {
                if let Ok(packet) = packet_parser(raw.data) {
                    sender.try_send(SnifferEvent::Packet(Arc::new(packet)));
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => return Err(format!("Capture error: {e}")),
        }
    }

    Ok(())
}

// ───────────────────────────── Parsing ─────────────────────────────

pub fn packet_parser(raw: &[u8]) -> Result<Packet, ParseError> {
    let (ethernet, rest) = parse_ethernet(raw)?;
    let ether_type = ethernet.ether_type;

    let mut packet = Packet {
        ethernet,
        network: None,
        transport: None,
        payload: Vec::new(),
    };

    match ether_type {
        // IPv4
        0x0800 => {
            let (ipv4, payload) = parse_ipv4(rest)?;

            let protocol = ipv4.protocol;
            let first_fragment = ipv4.fragment_offset == 0;

            packet.network = Some(NetworkLayer::IPv4(ipv4));

            if first_fragment {
                let (transport, payload) = parse_transport(protocol, payload);
                packet.transport = transport;
                packet.payload = payload.to_vec();
            } else {
                packet.payload = payload.to_vec();
            }
        }

        // IPv6
        0x86DD => {
            let (ipv6, payload) = parse_ipv6(rest)?;

            let next_header = ipv6.next_header;

            packet.network = Some(NetworkLayer::IPv6(ipv6));

            let (transport, payload) = parse_transport(next_header, payload);
            packet.transport = transport;
            packet.payload = payload.to_vec();
        }

        // ARP
        0x0806 => {
            let (arp, payload) = parse_arp(rest)?;

            packet.network = Some(NetworkLayer::Arp(arp));
            packet.payload = payload.to_vec();
        }

        _ => {
            packet.payload = rest.to_vec();
        }
    }

    Ok(packet)
}

/// Shared by IPv4 and IPv6. Unknown protocols and parse errors give `None`
/// and leave the data untouched.
fn parse_transport(protocol: u8, raw: &[u8]) -> (Option<TransportLayer>, &[u8]) {
    let parsed = match protocol {
        6 => parse_tcp(raw)
            .ok()
            .map(|(h, rest)| (TransportLayer::Tcp(h), rest)),
        17 => parse_udp(raw)
            .ok()
            .map(|(h, rest)| (TransportLayer::Udp(h), rest)),
        1 => parse_icmp(raw)
            .ok()
            .map(|(h, rest)| (TransportLayer::Icmp(h), rest)),
        58 => parse_icmpv6(raw)
            .ok()
            .map(|(h, rest)| (TransportLayer::Icmpv6(h), rest)),
        _ => None,
    };

    parsed.map_or((None, raw), |(transport, rest)| (Some(transport), rest))
}

pub fn parse_ethernet(raw: &[u8]) -> Result<(EthernetHeader, &[u8]), ParseError> {
    if raw.len() < 14 {
        return Err(ParseError::MalformedPacket);
    }

    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];

    dst_mac.copy_from_slice(&raw[0..6]);
    src_mac.copy_from_slice(&raw[6..12]);

    let mut ether_type = u16::from_be_bytes([raw[12], raw[13]]);
    let mut offset = 14;

    // VLAN tag (802.1Q / 802.1ad): the real EtherType follows the 4-byte tag
    if matches!(ether_type, 0x8100 | 0x88A8) {
        if raw.len() < 18 {
            return Err(ParseError::MalformedPacket);
        }
        ether_type = u16::from_be_bytes([raw[16], raw[17]]);
        offset = 18;
    }

    Ok((
        EthernetHeader {
            src_mac,
            dst_mac,
            ether_type,
        },
        &raw[offset..],
    ))
}

pub fn parse_ipv4(raw: &[u8]) -> Result<(IPv4Header, &[u8]), ParseError> {
    if raw.len() < 20 {
        return Err(ParseError::MalformedPacket);
    }

    let [version, ihl] = byte_to_2x4bits(raw[0]);

    if version != 4 || ihl < 5 {
        return Err(ParseError::MalformedPacket);
    }

    let header_len = ihl as usize * 4;

    if raw.len() < header_len {
        return Err(ParseError::MalformedPacket);
    }

    let dscp = raw[1] >> 2;
    let ecn = raw[1] & 0b11;

    let total_length = u16::from_be_bytes([raw[2], raw[3]]);
    let identification = u16::from_be_bytes([raw[4], raw[5]]);

    let reserved = (raw[6] >> 7) & 1;
    let dont_fragment = (raw[6] >> 6) & 1;
    let more_fragments = (raw[6] >> 5) & 1;

    let fragment_offset = u16::from_be_bytes([raw[6], raw[7]]) & 0x1FFF;

    let ttl = raw[8];
    let protocol = raw[9];
    let checksum = u16::from_be_bytes([raw[10], raw[11]]);

    let src = Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]);
    let dst = Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]);

    let header = IPv4Header {
        version,
        ihl,
        dscp,
        ecn,
        total_length,
        identification,
        reserved,
        dont_fragment,
        more_fragments,
        fragment_offset,
        ttl,
        protocol,
        checksum,
        src,
        dst,
    };

    let total = total_length as usize;
    let end = if total >= header_len && total <= raw.len() {
        total
    } else {
        raw.len()
    };

    Ok((header, &raw[header_len..end]))
}

pub fn parse_ipv6(raw: &[u8]) -> Result<(IPv6Header, &[u8]), ParseError> {
    if raw.len() < 40 {
        return Err(ParseError::MalformedPacket);
    }

    let version = raw[0] >> 4;

    if version != 6 {
        return Err(ParseError::MalformedPacket);
    }

    let traffic_class = ((raw[0] & 0x0F) << 4) | (raw[1] >> 4);

    let flow_label = ((raw[1] as u32 & 0x0F) << 16) | ((raw[2] as u32) << 8) | raw[3] as u32;

    let payload_length = u16::from_be_bytes([raw[4], raw[5]]);

    let next_header = raw[6];
    let hop_limit = raw[7];

    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];

    src.copy_from_slice(&raw[8..24]);
    dst.copy_from_slice(&raw[24..40]);

    let header = IPv6Header {
        version,
        traffic_class,
        flow_label,
        payload_length,
        next_header,
        hop_limit,
        src,
        dst,
    };

    let plen = payload_length as usize;
    let end = if plen != 0 && 40 + plen <= raw.len() {
        40 + plen
    } else {
        raw.len()
    };

    Ok((header, &raw[40..end]))
}

fn parse_tcp(raw: &[u8]) -> Result<(TcpHeader, &[u8]), ParseError> {
    if raw.len() < 20 {
        return Err(ParseError::MalformedPacket);
    }

    let src_port = u16::from_be_bytes([raw[0], raw[1]]);
    let dst_port = u16::from_be_bytes([raw[2], raw[3]]);

    let seq = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let ack = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);

    let data_offset = raw[12] >> 4;

    // a header shorter than 20 bytes is invalid (and would underflow below)
    if data_offset < 5 {
        return Err(ParseError::MalformedPacket);
    }

    let flags_byte = raw[13];

    let flags = TcpFlags {
        fin: flags_byte & 0x01 != 0,
        syn: flags_byte & 0x02 != 0,
        rst: flags_byte & 0x04 != 0,
        psh: flags_byte & 0x08 != 0,
        ack: flags_byte & 0x10 != 0,
        urg: flags_byte & 0x20 != 0,
        ece: flags_byte & 0x40 != 0,
        cwr: flags_byte & 0x80 != 0,
    };

    let window_size = u16::from_be_bytes([raw[14], raw[15]]);
    let checksum = u16::from_be_bytes([raw[16], raw[17]]);
    let urgent_pointer = u16::from_be_bytes([raw[18], raw[19]]);

    let header_length = data_offset as usize * 4;

    if raw.len() < header_length {
        return Err(ParseError::MalformedPacket);
    }

    // broken options should not hide the whole packet
    let options = parse_tcp_options(&raw[20..header_length]).unwrap_or_default();

    let header = TcpHeader {
        src_port,
        dst_port,
        seq,
        ack,
        data_offset,
        flags,
        window_size,
        checksum,
        urgent_pointer,
        options,
    };

    Ok((header, &raw[header_length..]))
}

pub fn parse_tcp_options(raw: &[u8]) -> Result<Vec<TcpOption>, ParseError> {
    let mut options = Vec::new();
    let mut offset = 0;

    while offset < raw.len() {
        let kind = raw[offset];

        match kind {
            // End of options
            0 => {
                options.push(TcpOption::End);
                break;
            }

            // NOP
            1 => {
                options.push(TcpOption::NoOperation);
                offset += 1;
            }

            _ => {
                if offset + 1 >= raw.len() {
                    return Err(ParseError::MalformedPacket);
                }

                let length = raw[offset + 1] as usize;

                if length < 2 || offset + length > raw.len() {
                    return Err(ParseError::MalformedPacket);
                }

                let data = &raw[offset + 2..offset + length];

                match kind {
                    // MSS
                    2 => {
                        if data.len() != 2 {
                            return Err(ParseError::MalformedPacket);
                        }
                        let value = u16::from_be_bytes([data[0], data[1]]);
                        options.push(TcpOption::MaximumSegmentSize { value });
                    }

                    // Window scaling
                    3 => {
                        if data.len() != 1 {
                            return Err(ParseError::MalformedPacket);
                        }
                        options.push(TcpOption::WindowScale { shift: data[0] });
                    }

                    // SACK permitted
                    4 => {
                        options.push(TcpOption::SackPermitted);
                    }

                    // Timestamp
                    8 => {
                        if data.len() != 8 {
                            return Err(ParseError::MalformedPacket);
                        }
                        let ts_value = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                        let ts_echo = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                        options.push(TcpOption::Timestamp { ts_value, ts_echo });
                    }

                    _ => {
                        options.push(TcpOption::Unknown {
                            kind,
                            data: data.to_vec(),
                        });
                    }
                }

                offset += length;
            }
        }
    }

    Ok(options)
}

pub fn parse_udp(raw: &[u8]) -> Result<(UdpHeader, &[u8]), ParseError> {
    if raw.len() < 8 {
        return Err(ParseError::MalformedPacket);
    }

    let src_port = u16::from_be_bytes([raw[0], raw[1]]);
    let dst_port = u16::from_be_bytes([raw[2], raw[3]]);
    let length = u16::from_be_bytes([raw[4], raw[5]]);
    let checksum = u16::from_be_bytes([raw[6], raw[7]]);

    // With offloading the length field can be 0 or too large: use the remainder.
    let len = length as usize;
    let end = if len >= 8 && len <= raw.len() {
        len
    } else {
        raw.len()
    };

    let header = UdpHeader {
        src_port,
        dst_port,
        length,
        checksum,
    };

    Ok((header, &raw[8..end]))
}

pub fn parse_icmp(raw: &[u8]) -> Result<(IcmpHeader, &[u8]), ParseError> {
    if raw.len() < 4 {
        return Err(ParseError::MalformedPacket);
    }

    let header = IcmpHeader {
        icmp_type: raw[0],
        code: raw[1],
        checksum: u16::from_be_bytes([raw[2], raw[3]]),
    };

    Ok((header, &raw[4..]))
}

pub fn parse_icmpv6(raw: &[u8]) -> Result<(Icmpv6Header, &[u8]), ParseError> {
    if raw.len() < 4 {
        return Err(ParseError::MalformedPacket);
    }

    let header = Icmpv6Header {
        icmp_type: raw[0],
        code: raw[1],
        checksum: u16::from_be_bytes([raw[2], raw[3]]),
    };

    Ok((header, &raw[4..]))
}

pub fn parse_arp(raw: &[u8]) -> Result<(ArpHeader, &[u8]), ParseError> {
    if raw.len() < 8 {
        return Err(ParseError::MalformedPacket);
    }

    let hardware_type = u16::from_be_bytes([raw[0], raw[1]]);
    let protocol_type = u16::from_be_bytes([raw[2], raw[3]]);

    let hardware_len = raw[4];
    let protocol_len = raw[5];

    let operation = u16::from_be_bytes([raw[6], raw[7]]);

    let hlen = hardware_len as usize;
    let plen = protocol_len as usize;

    let header_size = 8 + hlen + plen + hlen + plen;

    if raw.len() < header_size {
        return Err(ParseError::MalformedPacket);
    }

    let mut offset = 8;

    let sender_hardware_addr = raw[offset..offset + hlen].to_vec();
    offset += hlen;

    let sender_protocol_addr = raw[offset..offset + plen].to_vec();
    offset += plen;

    let target_hardware_addr = raw[offset..offset + hlen].to_vec();
    offset += hlen;

    let target_protocol_addr = raw[offset..offset + plen].to_vec();
    offset += plen;

    let header = ArpHeader {
        hardware_type,
        protocol_type,

        hardware_len,
        protocol_len,

        operation,

        sender_hardware_addr,
        sender_protocol_addr,

        target_hardware_addr,
        target_protocol_addr,
    };

    Ok((header, &raw[offset..]))
}

// ───────────────────────────── Small helpers ─────────────────────────────

fn bytes_to_hex(bytes: &[u8], join_char: &str) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(join_char)
}

fn byte_to_2x4bits(byte: u8) -> [u8; 2] {
    [(byte >> 4) & 0b1111, byte & 0b1111]
}
