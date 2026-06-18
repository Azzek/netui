use crate::{events::Event, traits::AppMod};
use pcap::Device;
use ratatui::{crossterm::event::KeyCode, text::Line, widgets::Paragraph};
use tokio::sync::mpsc::Sender;

pub struct SnifferMod {
    packets: Vec<String>,
}

impl SnifferMod {
    pub fn start(&mut self, tx: Sender<Event>) {
        tokio::task::spawn_blocking(move || {
            background_sniffing(tx);
        });
    }

    pub fn new() -> Self {
        Self {
            packets: vec![String::from("xdddddddd")],
        }
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
                let dst_mac = raw[0..6]
                    .iter()
                    .map(|b| format!("{:X}", b))
                    .collect::<Vec<_>>()
                    .join(" ");

                let src_mac = raw[6..12]
                    .iter()
                    .map(|b| format!("{:X}", b))
                    .collect::<Vec<_>>()
                    .join(" ");

                let ether_type = u16::from_be_bytes([raw[12], raw[13]]);

                let ip_type = match ether_type {
                    0x0800 => "IPv4",
                    0x86DD => "IPv6",
                    0x0806 => "ARP",
                    _ => "Unknown: 0x",
                };

                let info_str = format!("src: {}, dst: {}, ipv4: {}", src_mac, dst_mac, ip_type);
                self.packets.push(info_str);
            }
            Event::Key(k) => match k.code {
                KeyCode::Char('s') => self.start(tx),
                KeyCode::Char('l') => self.packets.push(format!("{}", self.packets.len())),
                KeyCode::Char('c') => self.packets.clear(),
                _ => {}
            },
            _ => {}
        }
    }
    fn render(&self, f: &mut ratatui::Frame, area: ratatui::layout::Rect, _: &crate::app::App) {
        let lines: Vec<Line> = self
            .packets
            .iter()
            .map(|p| Line::from(p.as_str()))
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
