use std::{fmt, net::Ipv4Addr};

use crate::{events::Event, traits::AppMod};
use pcap::Device;
use ratatui::{
    Frame,
    crossterm::event::KeyCode,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};
use tokio::sync::mpsc::Sender;

pub enum ParseError {
    InvalidSomething,
    MalformedPacket,
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

    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],

    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
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
}

pub struct SnifferMod {
    state: SnifferModState,
}

impl SnifferMod {
    pub fn new() -> Self {
        let mod_state = SnifferModState {
            packets: Vec::new(),
            selected_packet: 0,
        };
        Self { state: mod_state }
    }

    pub fn start(&mut self, tx: Sender<Event>) {
        tokio::task::spawn_blocking(move || {
            background_sniffing(tx);
        });
    }
}
impl AppMod for SnifferMod {
    fn update(
        &mut self,
        event: crate::events::Event,
        tx: tokio::sync::mpsc::Sender<crate::events::Event>,
    ) {
        match event {
            Event::PacketFound(raw) => {
                let packet_parse = packet_parser(&raw);
                if let Ok(packet) = packet_parse {
                    self.state.packets.push(packet);
                }
            }
            Event::Key(k) => match k.code {
                KeyCode::Char('s') => self.start(tx),
                // KeyCode::Char('l') => self.state.packets.push()),
                KeyCode::Char('c') => self.state.packets.clear(),
                _ => {}
            },
            _ => {}
        }
    }

    fn render(&self, f: &mut Frame, area: Rect, _: &crate::app::App) {
        let packets: Vec<Line> = self
            .state
            .packets
            .iter()
            .enumerate()
            .flat_map(|(i, p)| {
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

                vec![
                    // HEADER PACKET
                    Line::from(vec![
                        Span::raw(format!("[{}] ", i)),
                        Span::styled("ETH ", ratatui::style::Style::default().bold()),
                        Span::raw(format!("src={} dst={}", src, dst)),
                    ]),
                    // ETHER TYPE
                    Line::from(vec![
                        Span::raw("    ether: "),
                        Span::styled(
                            ether,
                            ratatui::style::Style::default().fg(ratatui::style::Color::Cyan),
                        ),
                    ]),
                    // NETWORK
                    Line::from(vec![Span::raw("    net: "), Span::raw(network_info)]),
                    // SEPARATOR
                    Line::from(Span::styled(
                        separator,
                        ratatui::style::Style::default().fg(ratatui::style::Color::DarkGray),
                    )),
                ]
            })
            .collect();

        let paragraph = Paragraph::new(packets).wrap(ratatui::widgets::Wrap { trim: true });

        f.render_widget(paragraph, area);
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
    let (ethernet, rest) = parse_ethernet(raw)?;

    let mut packet = Packet {
        ethernet,
        network: None,
        transport: None,
        payload: Vec::new(),
    };

    match packet.ethernet.ether_type {
        0x0800 => {
            let (ipv4, rest) = parse_ipv4(rest)?;
            packet.network = Some(NetworkLayer::IPv4(ipv4));

            // match ipv4.protocol {
            //     6 => {
            //         let (tcp, rest) = parse_tcp(rest)?;
            //         packet.transport = Some(TransportHeader::TCP(tcp));
            //         packet.payload = rest.to_vec();
            //     }
            //     17 => { ... }
            // }

            packet.payload = rest.to_vec();
        }

        0x86DD => {
            let (ipv6, rest) = parse_ipv6(rest)?;
            packet.network = Some(NetworkLayer::IPv6(ipv6));
            packet.payload = rest.to_vec();
        }

        0x0806 => {
            // let (arp, rest) = parse_arp(rest)?;
            // packet.network = Some(NetworkLayer::Arp(arp));
            // packet.payload = rest.to_vec();
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
