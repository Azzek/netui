use std::{fmt, net::Ipv4Addr};

use crate::{events::Event, traits::AppMod};
use pcap::Device;
use ratatui::{
    Frame,
    crossterm::event::KeyCode,
    layout::Rect,
    prelude::Color,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, List, ListItem, ListState, Scrollbar, ScrollbarOrientation, ScrollbarState,
    },
};
use tokio::sync::mpsc::Sender;

pub enum ParseError {
    InvalidSomething,
    MalformedPacket,
    UnsupportedProtocol,
}

#[derive(Debug)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

impl EthernetHeader {
    pub fn ether_type_str(&self) -> String {
        match self.ether_type {
            0x0800 => "IPv4",
            0x86DD => "IPv6",
            0x0806 => "ARP",
            _ => "Unknown: 0x",
        }
        .to_string()
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

    // pub flags: u8,
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

pub struct SnifferModState {
    packets: Vec<Packet>,
    selected_packet: usize,
    is_running: bool,
    max_packets: usize,
    auto_scroll: bool,
}

pub struct SnifferMod {
    state: SnifferModState,
}

impl SnifferMod {
    pub fn new() -> Self {
        let mod_state = SnifferModState {
            packets: Vec::with_capacity(1000),
            selected_packet: 0,
            is_running: false,
            max_packets: 1000,
            auto_scroll: true,
        };
        Self { state: mod_state }
    }

    pub fn start(&mut self, tx: Sender<Event>) {
        if (!self.state.is_running) {
            tokio::task::spawn_blocking(move || {
                background_sniffing(tx);
            });
        } else {
            // communicate that is running (later)
        }
    }

    pub fn stop(&mut self, tx: Sender<Event>) {
        // stop
    }
}

impl AppMod for SnifferMod {
    fn update(
        &mut self,
        event: crate::events::Event,
        tx: tokio::sync::mpsc::Sender<crate::events::Event>,
    ) {
        match event {
            // MOD EVENTS
            Event::PacketFound(raw) => {
                if let Ok(packet) = packet_parser(&raw) {
                    if self.state.packets.len() >= self.state.max_packets {
                        self.state.packets.remove(0);
                    }
                    self.state.packets.push(packet);

                    if self.state.auto_scroll && !self.state.packets.is_empty() {
                        self.state.selected_packet = self.state.packets.len() - 1;
                    }
                }
            }
            // MOD CONTROLS
            Event::Key(k) => match k.code {
                KeyCode::Char('s') => self.start(tx),
                KeyCode::Char('d') => self.stop(tx),
                KeyCode::Char('c') => self.state.packets.clear(),

                // PACKET LIST CONTROLS
                KeyCode::Down | KeyCode::Char('j') => {
                    if !self.state.packets.is_empty() {
                        if self.state.selected_packet < self.state.packets.len() - 1 {
                            self.state.selected_packet += 1;
                        }
                    }
                }

                KeyCode::Up | KeyCode::Char('k') => {
                    if self.state.selected_packet > 0 {
                        self.state.selected_packet -= 1;
                    }
                }

                KeyCode::Enter => {
                    if let Some(packet) = self.state.packets.get(self.state.selected_packet) {
                        // DO SOMETHING
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    fn render(&self, f: &mut Frame, area: Rect, _: &crate::app::App) {
        let items: Vec<ListItem> = self
            .state
            .packets
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let src = bytes_to_hex(&p.ethernet.src_mac, ":");
                let dst = bytes_to_hex(&p.ethernet.dst_mac, ":");
                let ether = p.ethernet.ether_type_str();

                let network_info = match &p.network {
                    Some(NetworkLayer::IPv4(ipv4)) => format!("{}", ipv4),
                    Some(NetworkLayer::IPv6(ipv6)) => format!("{:?}", ipv6),
                    Some(NetworkLayer::Arp(arp)) => format!("{:?}", arp),
                    None => "No network layer".to_string(),
                };

                let separator = "─".repeat(60);

                let packet_lines = vec![
                    // HEADER PACKET
                    Line::from(vec![
                        Span::raw(format!("[{}] ", i)),
                        Span::styled("ETH ", Style::default().bold()),
                        Span::raw(format!("src={} dst={}", src, dst)),
                    ]),
                    // ETHER TYPE
                    Line::from(vec![
                        Span::raw("    ether: "),
                        Span::styled(ether, Style::default().fg(Color::Cyan)),
                    ]),
                    // NETWORK
                    Line::from(vec![Span::raw("    net: "), Span::raw(network_info)]),
                    // TRANSPORT
                    Line::from(Span::styled(
                        format!("{:?}", p.transport),
                        Style::default().fg(Color::Blue),
                    )),
                    // SEPARATOR
                    Line::from(Span::styled(
                        separator,
                        Style::default().fg(Color::DarkGray),
                    )),
                ];

                ListItem::new(packet_lines)
            })
            .collect();

        let list = List::new(items)
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");

        let mut list_state = ListState::default();
        if !self.state.packets.is_empty() {
            list_state.select(Some(self.state.selected_packet));
        }

        f.render_stateful_widget(list, area, &mut list_state);

        if !self.state.packets.is_empty() {
            let mut scrollbar_state =
                ScrollbarState::new(self.state.packets.len()).position(self.state.selected_packet);

            let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▲"))
                .end_symbol(Some("▼"))
                .track_symbol(Some("│"))
                .thumb_symbol("█");

            f.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
        }
    }

    fn captures_input(&self) -> bool {
        false
    }

    fn instructions(&self) -> Vec<String> {
        vec!["Todo".to_string()]
    }
}

fn background_sniffing(tx: Sender<Event>) {
    let device = match Device::lookup() {
        Ok(Some(device)) => device,
        Ok(None) => {
            eprintln!("No default network interface found.");
            return;
        }
        Err(err) => {
            eprintln!("Failed to lookup network interface: {err}");
            return;
        }
    };

    let mut cap = match device.open() {
        Ok(cap) => cap,
        Err(err) => {
            eprintln!("Failed to open capture device: {err}");
            return;
        }
    };

    while let Ok(packet) = cap.next_packet() {
        if tx
            .blocking_send(Event::PacketFound(packet.to_vec()))
            .is_err()
        {
            break;
        }
    }
}

pub fn packet_parser(raw: &[u8]) -> Result<Packet, ParseError> {
    let (ethernet, mut rest) = parse_ethernet(raw)?;

    let mut packet = Packet {
        ethernet,
        network: None,
        transport: None,
        payload: Vec::new(),
    };

    match packet.ethernet.ether_type {
        // IPv4
        0x0800 => {
            let (ipv4, payload) = parse_ipv4(rest)?;

            let protocol = ipv4.protocol;

            packet.network = Some(NetworkLayer::IPv4(ipv4));

            rest = payload;

            match protocol {
                // TCP
                6 => {
                    let (tcp, payload) = parse_tcp(rest)?;

                    packet.transport = Some(TransportLayer::Tcp(tcp));

                    packet.payload = payload.to_vec();
                }

                // UDP
                17 => {
                    let (udp, payload) = parse_udp(rest)?;

                    packet.transport = Some(TransportLayer::Udp(udp));

                    packet.payload = payload.to_vec();
                }

                // ICMP
                1 => {
                    // let (icmp, payload) = parse_icmp(rest)?;

                    // packet.transport = Some(TransportLayer::Icmp(icmp));

                    // packet.payload = payload.to_vec();
                }

                _ => {
                    packet.payload = rest.to_vec();
                }
            }
        }

        // IPv6
        0x86DD => {
            let (ipv6, payload) = parse_ipv6(rest)?;

            let next_header = ipv6.next_header;

            packet.network = Some(NetworkLayer::IPv6(ipv6));

            rest = payload;

            match next_header {
                // TCP
                6 => {
                    let (tcp, payload) = parse_tcp(rest)?;

                    packet.transport = Some(TransportLayer::Tcp(tcp));

                    packet.payload = payload.to_vec();
                }

                // UDP
                17 => {
                    let (udp, payload) = parse_udp(rest)?;

                    packet.transport = Some(TransportLayer::Udp(udp));

                    packet.payload = payload.to_vec();
                }

                // ICMPv6
                58 => {
                    // let (icmp, payload) = parse_icmpv6(rest)?;

                    // packet.transport = Some(TransportLayer::Icmpv6(icmp));

                    // packet.payload = payload.to_vec();
                }

                _ => {
                    packet.payload = rest.to_vec();
                }
            }
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

pub fn parse_ethernet(raw: &[u8]) -> Result<(EthernetHeader, &[u8]), ParseError> {
    if raw.len() < 14 {
        return Err(ParseError::MalformedPacket);
    }

    let mut dst_mac = [0u8; 6];

    let mut src_mac = [0u8; 6];

    dst_mac.copy_from_slice(&raw[0..6]);

    src_mac.copy_from_slice(&raw[6..12]);

    let ether_type = u16::from_be_bytes([raw[12], raw[13]]);

    Ok((
        EthernetHeader {
            src_mac,
            dst_mac,
            ether_type,
        },
        &raw[14..],
    ))
}

pub fn parse_ipv4(raw: &[u8]) -> Result<(IPv4Header, &[u8]), ParseError> {
    if raw.len() < 20 {
        return Err(ParseError::MalformedPacket);
    }

    let [version, ihl] = byte_to_2x4bits(raw[0]);

    if version != 4 {
        return Err(ParseError::MalformedPacket);
    }

    if ihl < 5 {
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

    let src = std::net::Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]);

    let dst = std::net::Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]);

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

    Ok((header, &raw[header_len..]))
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

    Ok((header, &raw[40..]))
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

    let header_length = (data_offset * 4) as usize;

    if raw.len() < header_length {
        return Err(ParseError::MalformedPacket);
    }

    let options_length = header_length - 20;

    let options = if options_length > 0 {
        parse_tcp_options(&raw[20..header_length])?
    } else {
        Vec::new()
    };

    let payload = &raw[header_length..];

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

    Ok((header, payload))
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

    if length < 8 {
        return Err(ParseError::MalformedPacket);
    }

    let length = length as usize;

    if raw.len() < length {
        return Err(ParseError::MalformedPacket);
    }

    let header = UdpHeader {
        src_port,
        dst_port,
        length: length as u16,
        checksum,
    };

    Ok((header, &raw[8..length]))
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
