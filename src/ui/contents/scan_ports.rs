use std::{net::IpAddr, str::FromStr, sync::Arc, time::Duration};

use ratatui::{
    Frame,
    crossterm::event::KeyCode,
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, List, ListItem, Widget},
};
use tokio::{
    net::TcpStream,
    sync::{Mutex, mpsc::Sender},
    task::JoinSet,
    time::timeout,
};

use crate::{
    app::App,
    events::Event,
    ui::{components::button::Button, contents::content::Content},
};

pub struct Port {
    pub port: u32,
    pub conn_type: ConnType,
}

impl Port {
    pub fn new(port: u32, conn_type: ConnType) -> Self {
        Self { port, conn_type }
    }
}

pub enum ConnType {
    Udp,
    Tcp,
}

impl ConnType {
    pub fn as_str(&self) -> &str {
        match self {
            ConnType::Udp => "UDP",
            ConnType::Tcp => "TCP",
        }
    }
}

pub struct ScanState {
    pub ports: Vec<Port>,
    pub is_scanning: bool,
}

pub struct PortsContent {
    pub state: Arc<Mutex<ScanState>>,
    buttons: Vec<Button>,
}

impl PortsContent {
    pub fn new() -> Self {
        let buttons = vec![
            Button::new("Scan".to_string(), true),
            Button::new("Stop".to_string(), false),
        ];
        let state = Arc::new(Mutex::new(ScanState {
            ports: Vec::new(),
            is_scanning: false,
        }));
        Self { buttons, state }
    }

    pub fn scan_ports(&mut self) {
        if let Ok(mut s) = self.state.try_lock() {
            if s.is_scanning {
                return;
            }
            s.is_scanning = true;
            s.ports.clear();
        }

        let state = self.state.clone();
        let ip_str = String::from("8.8.8.8");

        tokio::spawn(async move {
            let mut ports_range = 1u16..=65535;
            let mut set: JoinSet<Result<u16, String>> = JoinSet::new();

            for _ in 0..200 {
                if let Some(port) = ports_range.next() {
                    let ip = IpAddr::from_str(&ip_str).expect("zjebany ip XXXXXXX");
                    set.spawn(async move { scan_tcp(ip, port).await });
                }
            }

            while let Some(result) = set.join_next().await {
                if let Some(next_port) = ports_range.next() {
                    let ip = IpAddr::from_str(&ip_str).expect("zjebany ip XXXXXXX");
                    set.spawn(async move { scan_tcp(ip, next_port).await });
                }

                match result {
                    Ok(Ok(port)) => {
                        state
                            .lock()
                            .await
                            .ports
                            .push(Port::new(port as u32, ConnType::Tcp));
                    }
                    Ok(Err(_)) => {
                        // state
                        //     .lock()
                        //     .await
                        //     .ports
                        //     .push(Port::new(100 as u32, ConnType::Tcp));
                    } //
                    Err(e) => eprintln!("Błąd tasku: {:?}", e),
                }
            }

            state.lock().await.is_scanning = false;
        });
    }

    pub fn stop_scan(&mut self) {
        if let Ok(mut s) = self.state.try_lock() {
            s.is_scanning = false;
        }
    }
}

pub async fn scan_tcp(ip: IpAddr, port: u16) -> Result<u16, String> {
    let addr = std::net::SocketAddr::new(ip, port);
    match timeout(Duration::from_millis(2000), TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => Ok(port),
        Ok(Err(e)) => Err(format!("Port closed: {}", e)),
        Err(_) => Err("Filtered or timed out".to_string()),
    }
}

pub async fn scan_udp(ip: IpAddr, port: u16) -> Result<u16, String> {
    Ok(16) // let
}

impl Content for PortsContent {
    fn render(&self, frame: &mut Frame, area: Rect, _app: &App) {
        let buf = frame.buffer_mut();
        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(3)]).split(area);

        let Ok(state) = self.state.try_lock() else {
            Block::bordered()
                .title(" Ports ")
                .border_type(BorderType::Rounded)
                .border_style(Style::new().blue())
                .render(layout[0], buf);
            return;
        };

        let title = if state.is_scanning {
            " Ports [skanowanie...] "
        } else {
            " Ports "
        };

        let outer = Block::bordered()
            .title(title)
            .border_type(BorderType::Rounded)
            .border_style(Style::new().blue());

        if !state.ports.is_empty() {
            let items: Vec<ListItem> = state
                .ports
                .iter()
                .map(|port| {
                    let color = match port.conn_type {
                        ConnType::Tcp => Color::Green,
                        ConnType::Udp => Color::Cyan,
                    };
                    let line = Line::from(vec![
                        Span::styled(
                            format!("{:>5}  ", port.port),
                            Style::default().fg(Color::Gray),
                        ),
                        Span::styled(port.conn_type.as_str(), Style::default().fg(color)),
                    ]);
                    ListItem::new(line)
                })
                .collect();

            List::new(items).block(outer).render(layout[0], buf);
        } else {
            outer.render(layout[0], buf);
        }

        if self.buttons.is_empty() {
            return;
        }

        let btn_constraints: Vec<Constraint> =
            self.buttons.iter().map(|_| Constraint::Fill(1)).collect();

        let btn_areas = Layout::horizontal(btn_constraints).split(layout[1]);

        for (btn, btn_area) in self.buttons.iter().zip(btn_areas.iter()) {
            frame.render_widget(btn.to_owned(), *btn_area);
        }
    }

    fn controls(&mut self, key: KeyCode, _tx: &Sender<Event>) {
        if self.buttons.is_empty() {
            return;
        }

        if let Some(hover_index) = self.buttons.iter().position(|b| b.is_focused) {
            match key {
                KeyCode::Right => {
                    let next = (hover_index + 1) % self.buttons.len();
                    self.buttons[hover_index].is_focused = false;
                    self.buttons[next].is_focused = true;
                }
                KeyCode::Left => {
                    let prev = if hover_index == 0 {
                        self.buttons.len() - 1
                    } else {
                        hover_index - 1
                    };
                    self.buttons[hover_index].is_focused = false;
                    self.buttons[prev].is_focused = true;
                }
                KeyCode::Enter => match hover_index {
                    0 => self.scan_ports(),
                    1 => self.stop_scan(),
                    _ => {}
                },
                _ => {}
            }
        }
    }
}
