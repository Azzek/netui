use std::{
    cell::RefCell,
    net::{IpAddr, Ipv4Addr},
    ops::RangeToInclusive,
    str::FromStr,
};

use ratatui::{
    Frame,
    crossterm::event::KeyCode,
    layout::{Constraint, Layout, Margin, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Gauge, List, ListItem, ListState, Paragraph, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Sparkline, Widget,
    },
};
use tokio::sync::mpsc::Sender;

use crate::{
    app::App, events::Event, features::ports_scanner::launch_background_scan, traits::AppMod,
    ui::components::button::Button,
};

#[derive(Debug)]
pub struct Port {
    pub port: u16,
    pub state: String,
    pub service: String,
    pub banner: String,
    pub conn_type: ConnType,
}

#[derive(Debug)]
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

#[derive(PartialEq)]
pub enum ScanLabelStatus {
    Waiting,
    Scanning,
    Finished,
}

#[derive(Clone, Debug)]
enum ActiveSetting {
    TargetIP,
    PortRange,
    ScanSpeed,
}
impl ActiveSetting {
    pub fn to_line(&self, state: &ScanState, is_selected: bool) -> Line<'static> {
        let (label, value) = match self {
            &ActiveSetting::TargetIP => (" Target IP:   ", state.ip_address.to_string()),
            &ActiveSetting::PortRange => (" Port Range:  ", format!("{}-{}", 1, state.range.end,)),
            &ActiveSetting::ScanSpeed => (" Scan Speed:  ", format!("{} workers", state.max_speed)),
        };
        let (label_style, value_style) = if is_selected {
            (
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::UNDERLINED),
            )
        } else {
            (
                Style::default().fg(Color::White),
                Style::default().fg(Color::Gray),
            )
        };

        let prefix = if is_selected { " > " } else { "   " };

        Line::from(vec![
            Span::styled(prefix, Style::default().fg(Color::Yellow)),
            Span::styled(label, label_style),
            Span::styled(value, value_style),
        ])
    }

    pub const ALL_VARIANTS: [ActiveSetting; 3] = [
        ActiveSetting::TargetIP,
        ActiveSetting::PortRange,
        ActiveSetting::ScanSpeed,
    ];

    // pub fn name(&self) -> &'static str {
    //     match self {
    //         ActiveSetting::TargetIP => "Target IP Address",
    //         ActiveSetting::PortRange => "Range of Ports",
    //         ActiveSetting::ScanSpeed => "Scanning Speed (workers)",
    //     }
    // }
}

pub struct ScanState {
    pub scan_state: ScanLabelStatus,

    settings_popup_state: Option<Option<ActiveSetting>>,
    pub settings_list_state: RefCell<ListState>,
    pub validation_error: String,

    pub max_speed_buff: String,
    pub ip_buff: String,
    pub ip_address: IpAddr,

    pub range_buff: String,
    pub range: RangeToInclusive<u16>,

    pub max_speed: u32,

    pub ports: Vec<Port>,
    pub traffic_history: Vec<u64>,
    pub scan_progress: u32,
    pub current_probe: String,

    pub list_state: RefCell<ListState>,
}

pub struct PortsContent {
    pub state: ScanState,
    buttons: Vec<Button>,
}

impl PortsContent {
    pub fn new() -> Self {
        let buttons = vec![
            Button::new("Scan".to_string(), true),
            Button::new("IpAddr".to_string(), false),
        ];
        let state = ScanState {
            max_speed: 200,
            settings_list_state: RefCell::new(ListState::default()),
            range: RangeToInclusive { end: 10000 },
            range_buff: String::new(),
            max_speed_buff: String::new(),
            ports: Vec::new(),
            scan_state: ScanLabelStatus::Waiting,
            settings_popup_state: None,
            validation_error: String::new(),
            ip_buff: String::new(),
            ip_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            traffic_history: vec![0; 30],
            scan_progress: 0,
            current_probe: String::from("READY"),
            list_state: RefCell::new(ListState::default()),
        };
        Self { buttons, state }
    }

    pub fn start_scan(&mut self, tx: Sender<Event>) {
        if self.state.scan_state != ScanLabelStatus::Scanning {
            self.state.ports.clear();
            self.state.scan_state = ScanLabelStatus::Scanning;
            self.state.scan_progress = 0;
            self.state.current_probe = String::from("INITIALIZING NODE...");
            launch_background_scan(
                self.state.ip_address,
                tx,
                self.state.range,
                self.state.max_speed as u16,
            );
        }
    }
}

impl AppMod for PortsContent {
    fn render(&self, frame: &mut Frame, area: Rect, _app: &App) {
        let buf = frame.buffer_mut();

        let (title, title_color) = match self.state.scan_state {
            ScanLabelStatus::Waiting => (" [ SYSTEM IDLE: PORTS ] ", Color::Cyan),
            ScanLabelStatus::Scanning => (" [ BREACH IN PROGRESS: SCANNING... ] ", Color::Magenta),
            ScanLabelStatus::Finished => (" [ DATA EXTRACTION FINISHED ] ", Color::Green),
        };

        let outer = Block::bordered()
            .title(title)
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(title_color));

        let inner_area = outer.inner(area);
        outer.render(area, buf);

        let page_layout =
            Layout::vertical([Constraint::Percentage(30), Constraint::Percentage(70)])
                .split(inner_area);

        let info_layout =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(page_layout[0]);

        //------------- Left Panel: Settings
        let outer_settings = Block::bordered()
            .title(" [ TARGET CONFIG ] ")
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(Color::DarkGray));

        let inner_settings_area = outer_settings.inner(info_layout[0]);

        let settings_layout = Layout::vertical([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(34),
        ])
        .split(inner_settings_area);

        outer_settings.render(info_layout[0], buf);

        let ports_text = format!("TARGET_PORTS: 1..{}", self.state.range.end);
        let ip_text = format!("TARGET_NETNODE: {}", self.state.ip_address);
        let scan_speed_text = format!("SCAN_SPEED: {}", self.state.max_speed);

        let ports = Paragraph::new(ports_text).style(Style::new().fg(Color::Cyan));
        let ip = Paragraph::new(ip_text).style(Style::new().fg(Color::Cyan));
        let speed = Paragraph::new(scan_speed_text).fg(Color::Cyan);
        ports.render(settings_layout[0], buf);
        ip.render(settings_layout[1], buf);
        speed.render(settings_layout[2], buf);

        //Right Panel: Live Traffic & Sparkline Graph
        let outer_traffic = Block::bordered()
            .title(" [ LIVE TRAFFIC SPARKLINE ] ")
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(Color::DarkGray));

        let inner_traffic_area = outer_traffic.inner(info_layout[1]);
        outer_traffic.render(info_layout[1], buf);

        let right_panel_layout = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(inner_traffic_area);

        let progress_layout = Layout::horizontal([Constraint::Length(13), Constraint::Min(0)])
            .split(right_panel_layout[0]);

        let current_speed = self.state.traffic_history.last().copied().unwrap_or(0);
        let pkts_label = format!("Pkts/s: {:<3} ", current_speed);
        Paragraph::new(pkts_label)
            .style(Style::new().fg(Color::White))
            .render(progress_layout[0], buf);

        let progress_bar = Gauge::default()
            .percent(self.state.scan_progress as u16)
            .gauge_style(Style::default().fg(Color::Magenta).bg(Color::Indexed(236)))
            .use_unicode(false)
            .label(format!("{}%", self.state.scan_progress));
        progress_bar.render(progress_layout[1], buf);

        let probe_text = format!("Curr: {}", self.state.current_probe);
        Paragraph::new(probe_text)
            .style(Style::new().fg(Color::DarkGray))
            .render(right_panel_layout[1], buf);

        let sparkline = Sparkline::default()
            .data(&self.state.traffic_history)
            .max(250)
            .style(Style::default().fg(Color::Green));
        sparkline.render(right_panel_layout[2], buf);

        //------------- Bottom Panel: Data Pool
        if !self.state.ports.is_empty() {
            let items: Vec<ListItem> = self
                .state
                .ports
                .iter()
                .map(|port| {
                    let (state_label, state_color, glyph) = match port.state.as_str() {
                        "Open" => ("  [ONLINE]  ", Color::Magenta, "⚡"),
                        "Filtered" => (" [Filtered]  ", Color::Yellow, "🔒"),
                        _ => (" [OFFLINE]  ", Color::DarkGray, "✖"),
                    };

                    let conn_color = match port.conn_type {
                        ConnType::Tcp => Color::Green,
                        ConnType::Udp => Color::Cyan,
                    };

                    let hex_port = format!("0x{:04X}", port.port);
                    let dec_port = port.port;

                    let mut line_spans = vec![
                        Span::styled(
                            format!("// SYS_NET {glyph} ── "),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::styled(
                            format!("PORT {hex_port} "),
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(format!("({dec_port}) "), Style::default().fg(Color::White)),
                        Span::styled("── ", Style::default().fg(Color::DarkGray)),
                        Span::styled(
                            format!("[{}] ", port.conn_type.as_str()),
                            Style::default().fg(conn_color),
                        ),
                        Span::styled("── ", Style::default().fg(Color::DarkGray)),
                        Span::styled(
                            state_label,
                            Style::default()
                                .fg(state_color)
                                .add_modifier(Modifier::BOLD),
                        ),
                    ];

                    if port.state == "Open" {
                        line_spans.push(Span::styled("── ", Style::default().fg(Color::DarkGray)));
                        line_spans.push(Span::styled(
                            format!("srv: [{}] ", port.service),
                            Style::default().fg(Color::LightGreen),
                        ));

                        if port.banner != "No banner"
                            && !port.banner.is_empty()
                            && port.banner != "-"
                        {
                            line_spans.push(Span::styled(
                                format!("📡 sig: \"{}\"", port.banner),
                                Style::default().fg(Color::Indexed(244)),
                            ));
                        }
                    }

                    ListItem::new(Line::from(line_spans))
                })
                .collect();

            let list = List::new(items)
                .block(
                    Block::bordered()
                        .title(" ❖ [ CORE_NET_STREAM: CAPTURED_DATA_POOL ] ❖ ")
                        .border_type(BorderType::Double)
                        .border_style(Style::new().fg(Color::Magenta)),
                )
                .highlight_style(
                    Style::default()
                        .bg(Color::Indexed(235))
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol(" > ");

            let mut list_state = self.state.list_state.borrow_mut();
            frame.render_stateful_widget(list, page_layout[1], &mut *list_state);

            let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▓"))
                .end_symbol(Some("░"))
                .track_symbol(Some("│"))
                .thumb_symbol("█");

            let mut scrollbar_state = ScrollbarState::new(self.state.ports.len())
                .position(list_state.selected().unwrap_or(0));

            frame.render_stateful_widget(
                scrollbar,
                page_layout[1].inner(Margin {
                    vertical: 1,
                    horizontal: 0,
                }),
                &mut scrollbar_state,
            );
        } else {
            Block::bordered()
                .title(" ❖ [ STREAM OVERRIDE REQUIRED ] ❖ ")
                .border_type(BorderType::Rounded)
                .border_style(Style::new().fg(Color::Red))
                .render(page_layout[1], buf);
        }

        //------------- Modal Popup
        if let Some(selection) = &self.state.settings_popup_state {
            let popup_area = Layout::vertical([
                Constraint::Percentage(35),
                Constraint::Length(5),
                Constraint::Percentage(35),
            ])
            .split(frame.area())[1];

            let popup_area = Layout::horizontal([
                Constraint::Percentage(30),
                Constraint::Percentage(40),
                Constraint::Percentage(30),
            ])
            .split(popup_area)[1];

            if let Some(input_variant) = selection {
                match input_variant {
                    &ActiveSetting::TargetIP => {
                        let (label, border_color) = if self.state.validation_error.is_empty() {
                            (" >> Enter Target IP Address:", Color::Yellow)
                        } else {
                            (" [CRITICAL_ERR]: INVALID IP NODE COORD!", Color::Red)
                        };

                        let popup_text = vec![
                            Line::from(Span::styled(
                                label,
                                Style::default()
                                    .fg(border_color)
                                    .add_modifier(Modifier::BOLD),
                            )),
                            Line::from(""),
                            Line::from(format!("  NET_CMD > {}_", self.state.ip_buff)),
                        ];

                        let popup_widget = Paragraph::new(popup_text).block(
                            Block::bordered()
                                .title(" [ IDENTITY_GATEWAY_CONFIG ] ")
                                .border_type(BorderType::Double)
                                .border_style(Style::default().fg(border_color)),
                        );

                        frame.render_widget(ratatui::widgets::Clear, popup_area);
                        frame.render_widget(popup_widget, popup_area);
                    }
                    &ActiveSetting::PortRange => {
                        let (label, border_color) = if self.state.validation_error.is_empty() {
                            (" >> Enter new Ports Range", Color::Yellow)
                        } else {
                            (
                                " [CRITICAL_ERR]: Invalid format!\n valid formar: xx..xx",
                                Color::Red,
                            )
                        };

                        let popup_text = vec![
                            Line::from(Span::styled(
                                label,
                                Style::default()
                                    .fg(border_color)
                                    .add_modifier(Modifier::BOLD),
                            )),
                            Line::from(""),
                            Line::from(format!("  NET_CMD > {}_", self.state.range_buff)),
                        ];

                        let popup_widget = Paragraph::new(popup_text).block(
                            Block::bordered()
                                .title(" [ IDENTITY_GATEWAY_CONFIG ] ")
                                .border_type(BorderType::Double)
                                .border_style(Style::default().fg(border_color)),
                        );

                        frame.render_widget(ratatui::widgets::Clear, popup_area);
                        frame.render_widget(popup_widget, popup_area);
                    }
                    &ActiveSetting::ScanSpeed => {
                        let (label, border_color) = if self.state.validation_error.is_empty() {
                            (" >> Enter new Scan Speed", Color::Yellow)
                        } else {
                            (
                                " [CRITICAL_ERR]: Invalid input.\n only integers are allowed;",
                                Color::Red,
                            )
                        };

                        let popup_text = vec![
                            Line::from(Span::styled(
                                label,
                                Style::default()
                                    .fg(border_color)
                                    .add_modifier(Modifier::BOLD),
                            )),
                            Line::from(""),
                            Line::from(format!("  NET_CMD > {}_", self.state.max_speed_buff)),
                        ];

                        let popup_widget = Paragraph::new(popup_text).block(
                            Block::bordered()
                                .title(" [ IDENTITY_GATEWAY_CONFIG ] ")
                                .border_type(BorderType::Double)
                                .border_style(Style::default().fg(border_color)),
                        );

                        frame.render_widget(ratatui::widgets::Clear, popup_area);
                        frame.render_widget(popup_widget, popup_area);
                    }
                }
            } else {
                let list_items: Vec<ListItem> = ActiveSetting::ALL_VARIANTS
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        let list_state = self.state.settings_list_state.borrow_mut();
                        let selected = list_state.selected().unwrap_or(2);
                        if i == selected {
                            let line = v.to_line(&self.state, true);
                            ListItem::new(line)
                        } else {
                            let line = v.to_line(&self.state, false);
                            ListItem::new(line)
                        }
                    })
                    .collect();
                let settings_list = ratatui::widgets::List::new(list_items)
                    .block(ratatui::widgets::Block::bordered().title(" Settings "));

                frame.render_widget(settings_list, popup_area);
            }
        }
    }

    fn update(&mut self, event: Event, tx: Sender<Event>) {
        if self.buttons.is_empty() {
            return;
        }

        match event {
            Event::ScanProgress {
                progress,
                current_probe,
                pkts_s,
            } => {
                self.state.scan_progress = progress;
                self.state.current_probe = current_probe;

                self.state.traffic_history.push(pkts_s);

                if self.state.traffic_history.len() > 40 {
                    self.state.traffic_history.remove(0);
                }
            }
            Event::ScanFinished => {
                self.state.scan_state = ScanLabelStatus::Finished;
                self.state.scan_progress = 100;
                self.state.current_probe = String::from("SCAN COMPLETE.");
            }
            Event::PortFound(p) => {
                self.state.ports.push(p);
                let mut state = self.state.list_state.borrow_mut();
                state.select(Some(self.state.ports.len() - 1));
            }
            Event::Key(k) => {
                if let Some(state) = &self.state.settings_popup_state {
                    match state {
                        Some(s) => match s {
                            ActiveSetting::TargetIP => match k.code {
                                KeyCode::Char(c) => self.state.ip_buff.push(c),
                                KeyCode::Esc => {
                                    self.state.settings_popup_state = None;
                                }
                                KeyCode::Enter => {
                                    // let validation = IpAddr::from_str(self.state.ip_buff.as_str());
                                    if let Ok(ip) = IpAddr::from_str(self.state.ip_buff.as_str()) {
                                        self.state.ip_address = ip;
                                        self.state.settings_popup_state = None;
                                    } else {
                                        self.state.validation_error =
                                            String::from("[Error: Invalid IP]");
                                    }
                                }
                                _ => {}
                            },
                            ActiveSetting::PortRange => match k.code {
                                KeyCode::Char(c) => self.state.range_buff.push(c),
                                KeyCode::Backspace => {
                                    self.state.range_buff.pop();
                                }
                                KeyCode::Enter => {
                                    let parse_input: Result<u16, _> = self.state.range_buff.parse();
                                    if let Ok(range) = parse_input {
                                        let new_range = RangeToInclusive { end: range };
                                        self.state.range = new_range;
                                        self.state.settings_popup_state = None;
                                    } else {
                                        self.state.validation_error = String::from(
                                            "[Error: Invalid range] \n only integers are allowed.",
                                        );
                                    }
                                }
                                KeyCode::Esc => {
                                    self.state.settings_popup_state = None;
                                }
                                _ => {}
                            },
                            ActiveSetting::ScanSpeed => match k.code {
                                KeyCode::Char(c) => self.state.max_speed_buff.push(c),
                                KeyCode::Enter => {
                                    let validation_result = self.state.max_speed_buff.parse();
                                    if let Ok(max_speed) = validation_result {
                                        self.state.max_speed = max_speed;
                                        self.state.settings_popup_state = None;
                                    }
                                }
                                KeyCode::Esc => {
                                    self.state.settings_popup_state = None;
                                }

                                _ => {}
                            },
                        },
                        None => match k.code {
                            KeyCode::Esc => self.state.settings_popup_state = None,
                            KeyCode::Enter => {
                                let state = self.state.settings_list_state.borrow();
                                if let Some(i) = state.selected() {
                                    let variants: Vec<&ActiveSetting> =
                                        ActiveSetting::ALL_VARIANTS.iter().collect();
                                    let setting = variants[i].clone();
                                    self.state.settings_popup_state = Some(Some(setting));
                                }
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                let mut state = self.state.settings_list_state.borrow_mut();
                                let i = match state.selected() {
                                    Some(i) => {
                                        if i == 0 {
                                            ActiveSetting::ALL_VARIANTS.len() - 1
                                        } else {
                                            i - 1
                                        }
                                    }
                                    None => 0,
                                };
                                state.select(Some(i));
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                let mut state = self.state.settings_list_state.borrow_mut();

                                let i = match state.selected() {
                                    Some(i) => {
                                        if i >= ActiveSetting::ALL_VARIANTS.len() - 1 {
                                            0
                                        } else {
                                            i + 1
                                        }
                                    }
                                    None => 0,
                                };
                                state.select(Some(i));
                            }
                            _ => {}
                        },
                    }
                } else {
                    match k.code {
                        KeyCode::Up | KeyCode::Char('k') => {
                            let mut state = self.state.list_state.borrow_mut();
                            if !self.state.ports.is_empty() {
                                let i = match state.selected() {
                                    Some(i) => {
                                        if i == 0 {
                                            self.state.ports.len() - 1
                                        } else {
                                            i - 1
                                        }
                                    }
                                    None => 0,
                                };
                                state.select(Some(i));
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            let mut state = self.state.list_state.borrow_mut();
                            if !self.state.ports.is_empty() {
                                let i = match state.selected() {
                                    Some(i) => {
                                        if i >= self.state.ports.len() - 1 {
                                            0
                                        } else {
                                            i + 1
                                        }
                                    }
                                    None => 0,
                                };
                                state.select(Some(i));
                            }
                        }
                        KeyCode::F(5) => {
                            self.start_scan(tx);
                        }
                        KeyCode::F(9) => self.state.settings_popup_state = Some(None),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    fn instructions(&self) -> Vec<String> {
        Vec::from(["[F5: Scan]".to_string(), "[F9: Settings]".to_string()])
    }

    fn captures_input(&self) -> bool {
        self.state.settings_popup_state.is_some()
    }
}
