use std::{io::WriterPanicked, ops::RangeTo};

use crate::{events::Event, traits::AppMod};
use pcap::Device;
use ratatui::{crossterm::event::KeyCode, text::Line, widgets::Paragraph};
use tokio::sync::mpsc::Sender;

pub enum ParseError {
    InvalidSomething,
    MalformatedPacket,
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

    pub flags: u8,
    pub fragment_offset: u16,

    pub ttl: u8,
    pub protocol: u8,

    pub checksum: u16,

    pub src: [u8; 4],
    pub dst: [u8; 4],
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

// pub struct Packet {
//     dst_mac: String,
//     src_mac: String,
//     ether_type: String,
//     version: String,
// }

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
                let packet_parse = packet_parser(raw);
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

    fn render(&self, f: &mut ratatui::Frame, area: ratatui::layout::Rect, _: &crate::app::App) {
        let lines: Vec<Line> = self
            .state
            .packets
            .iter()
            .map(|p| {
                Line::from(format!(
                    "src: {}, dst: {}, ipv4: {}",
                    bytes_to_hex(&p.ethernet.src_mac, ":"),
                    bytes_to_hex(&p.ethernet.dst_mac, ":"),
                    p.ethernet.ether_type_str()
                ))
            })
            .collect();

        let paragraph = Paragraph::new(lines);

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
    let mut cap = Device::lookup().unwrap().unwrap().open().unwrap();

    while let Ok(packet) = cap.next_packet() {
        // println!("{:?}", packet)
        let _ = tx.blocking_send(Event::PacketFound(packet.to_vec()));
    }
}

fn packet_parser(packet: Vec<u8>) -> Result<Packet, ParseError> {
    let ethernet_parse = parse_ethernet(&packet[0..14]);
    if let Ok(ethernet) = ethernet_parse {
        let packet = Packet {
            ethernet,
            network: None,
            transport: None,
            payload: Vec::new(),
        };
        Ok(packet)
    } else {
        Err(ParseError::InvalidSomething)
    }
}

fn parse_ethernet(raw: &[u8]) -> Result<EthernetHeader, ParseError> {
    let dst_mac = raw[0..6].try_into().unwrap_or_default();

    let src_mac: [u8; 6] = raw[6..12].try_into().unwrap_or_default();

    let ether_type = u16::from_be_bytes([raw[12], raw[13]]);

    // let ether_type = match ether_type {
    //     0x0800 => "IPv4",
    //     0x86DD => "IPv6",
    //     0x0806 => "ARP",
    //     _ => "Unknown: 0x",
    // }
    // .to_string();

    Ok(EthernetHeader {
        src_mac,
        dst_mac,
        ether_type,
    })
}

fn bytes_to_hex(bytes: &[u8], join_char: &str) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(join_char)
}
