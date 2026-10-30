use core::fmt;
use std::{
    cell::RefCell,
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr},
    ops::RangeToInclusive,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use ratatui::{
    Frame,
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
    layout::{Constraint, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Clear, Gauge, List, ListItem, ListState, Paragraph, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Sparkline,
    },
};

use crate::{
    app::App,
    events::{Event, EventSender},
    features::ports_scanner::launch_background_scan,
    traits::AppMod,
};

const TRAFFIC_HISTORY_LEN: usize = 40;
const MAX_INPUT_LEN: usize = 45;
const POPUP_WIDTH: u16 = 60;

// ───────────────────────────── Events ─────────────────────────────

#[derive(Debug)]
pub enum ScanEvent {
    PortFound(Port),
    Progress {
        progress: u32,
        current_probe: String,
        pkts_s: u64,
    },
    Finished,
}

// ───────────────────────────── Data types ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortState::Open => write!(f, "Open"),
            PortState::Closed => write!(f, "Closed"),
            PortState::Filtered => write!(f, "Filtered"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnType {
    Udp,
    Tcp,
}

impl ConnType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnType::Udp => "UDP",
            ConnType::Tcp => "TCP",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Port {
    pub port: u16,
    pub state: PortState,
    pub service: String,
    pub banner: String,
    pub conn_type: ConnType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanLabelStatus {
    Waiting,
    Scanning,
    Finished,
}

// ───────────────────────────── Settings ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveSetting {
    TargetIp,
    PortRange,
    ScanSpeed,
    BufferCapacity,
}

impl ActiveSetting {
    const ALL: [ActiveSetting; 4] = [
        ActiveSetting::TargetIp,
        ActiveSetting::PortRange,
        ActiveSetting::ScanSpeed,
        ActiveSetting::BufferCapacity,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::TargetIp => "Target IP",
            Self::PortRange => "Port Range",
            Self::ScanSpeed => "Scan Speed",
            Self::BufferCapacity => "Buffer Capacity",
        }
    }

    fn prompt(self) -> &'static str {
        match self {
            Self::TargetIp => ">> Enter target IP address:",
            Self::PortRange => ">> Enter last port to scan (1-65535):",
            Self::ScanSpeed => ">> Enter number of workers (1-65535):",
            Self::BufferCapacity => ">> Enter max number of stored ports:",
        }
    }

    /// Human readable value shown in the settings menu.
    fn value(self, state: &ScanState) -> String {
        match self {
            Self::TargetIp => state.ip_address.to_string(),
            Self::PortRange => format!("1-{}", state.range.end),
            Self::ScanSpeed => format!("{} workers", state.max_speed),
            Self::BufferCapacity => state.max_cap.to_string(),
        }
    }

    /// Raw value used to prefill the input field when editing.
    fn raw_value(self, state: &ScanState) -> String {
        match self {
            Self::TargetIp => state.ip_address.to_string(),
            Self::PortRange => state.range.end.to_string(),
            Self::ScanSpeed => state.max_speed.to_string(),
            Self::BufferCapacity => state.max_cap.to_string(),
        }
    }

    fn to_line(self, state: &ScanState, is_selected: bool) -> Line<'static> {
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
            Span::styled(format!("{:<17}", format!("{}:", self.label())), label_style),
            Span::styled(self.value(state), value_style),
        ])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettingsPopup {
    Closed,
    Menu,
    Editing(ActiveSetting),
}

// ───────────────────────────── State ─────────────────────────────

pub struct ScanState {
    // scan
    pub scan_state: ScanLabelStatus,
    pub ports: VecDeque<Port>,
    pub list_state: RefCell<ListState>,
    pub traffic_history: Vec<u64>,
    pub scan_progress: u16,
    pub current_probe: String,

    // settings values
    pub ip_address: IpAddr,
    pub range: RangeToInclusive<u16>,
    pub max_speed: u16,
    pub max_cap: usize,

    // settings popup
    popup: SettingsPopup,
    pub settings_list_state: RefCell<ListState>,
    pub input_buff: String,
    pub validation_error: String,

    // set to true to ask the background scanner to stop
    stop: Arc<AtomicBool>,
}

pub struct PortsContent {
    pub state: ScanState,
}

impl Default for PortsContent {
    fn default() -> Self {
        Self::new()
    }
}

fn step(selected: Option<usize>, len: usize, delta: isize) -> usize {
    match selected {
        Some(i) => (i as isize + delta).rem_euclid(len as isize) as usize,
        None if delta >= 0 => 0,
        None => len - 1,
    }
}

fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

impl PortsContent {
    pub fn new() -> Self {
        let state = ScanState {
            scan_state: ScanLabelStatus::Waiting,
            ports: VecDeque::with_capacity(100),
            list_state: RefCell::new(ListState::default()),
            traffic_history: vec![0; TRAFFIC_HISTORY_LEN],
            scan_progress: 0,
            current_probe: String::from("READY"),

            ip_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            range: ..=10000,
            max_speed: 200,
            max_cap: 5,

            popup: SettingsPopup::Closed,
            settings_list_state: RefCell::new(ListState::default().with_selected(Some(0))),
            input_buff: String::new(),
            validation_error: String::new(),

            stop: Arc::new(AtomicBool::new(false)),
        };
        Self { state }
    }

    // ───────────── scan control ─────────────

    pub fn start_scan(&mut self, sender: &EventSender) {
        if self.state.scan_state == ScanLabelStatus::Scanning {
            return;
        }

        self.state.ports.clear();
        self.state.list_state.borrow_mut().select(None);
        self.state.traffic_history = vec![0; TRAFFIC_HISTORY_LEN];
        self.state.scan_state = ScanLabelStatus::Scanning;
        self.state.scan_progress = 0;
        self.state.current_probe = String::from("INITIALIZING NODE...");

        let stop = Arc::new(AtomicBool::new(false));
        self.state.stop = stop.clone();

        launch_background_scan(
            self.state.ip_address,
            sender,
            self.state.range,
            self.state.max_speed,
            stop,
        );
    }

    fn stop_scan(&mut self) {
        if self.state.scan_state == ScanLabelStatus::Scanning {
            self.state.stop.store(true, Ordering::Relaxed);
            self.state.current_probe = String::from("STOPPING SCAN...");
        }
    }

    // ───────────── scan events ─────────────

    fn on_scan_event(&mut self, ev: &ScanEvent) {
        match ev {
            ScanEvent::Progress {
                progress,
                current_probe,
                pkts_s,
            } => {
                self.state.scan_progress = (*progress).min(100) as u16;
                self.state.current_probe = current_probe.clone();

                let history = &mut self.state.traffic_history;
                history.push(*pkts_s);
                if history.len() > TRAFFIC_HISTORY_LEN {
                    let excess = history.len() - TRAFFIC_HISTORY_LEN;
                    history.drain(..excess);
                }
            }
            ScanEvent::Finished => {
                self.state.scan_state = ScanLabelStatus::Finished;
                if self.state.stop.load(Ordering::Relaxed) {
                    self.state.current_probe = String::from("SCAN STOPPED.");
                } else {
                    self.state.scan_progress = 100;
                    self.state.current_probe = String::from("SCAN COMPLETE.");
                }
            }
            ScanEvent::PortFound(port) => self.add_port(port.clone()),
        }
    }

    fn add_port(&mut self, port: Port) {
        self.state.ports.push_front(port);
        {
            let mut ls = self.state.list_state.borrow_mut();
            if let Some(i) = ls.selected() {
                ls.select(Some(i + 1));
            }
        }

        self.trim_ports();
    }

    fn trim_ports(&mut self) {
        while self.state.ports.len() > self.state.max_cap {
            let idx = self
                .state
                .ports
                .iter()
                .rposition(|p| p.state == PortState::Closed)
                .unwrap_or(self.state.ports.len() - 1);

            self.state.ports.remove(idx);

            let mut ls = self.state.list_state.borrow_mut();
            if let Some(i) = ls.selected() {
                if i > idx {
                    ls.select(Some(i - 1));
                }
            }
        }

        let len = self.state.ports.len();
        let mut ls = self.state.list_state.borrow_mut();
        match ls.selected() {
            Some(_) if len == 0 => ls.select(None),
            Some(i) if i >= len => ls.select(Some(len - 1)),
            _ => {}
        }
    }

    // ───────────── keys ─────────────

    fn move_port_selection(&mut self, delta: isize) {
        let len = self.state.ports.len();
        if len == 0 {
            return;
        }
        let mut ls = self.state.list_state.borrow_mut();
        let next = step(ls.selected(), len, delta);
        ls.select(Some(next));
    }

    fn move_menu_selection(&mut self, delta: isize) {
        let mut ls = self.state.settings_list_state.borrow_mut();
        let next = step(ls.selected(), ActiveSetting::ALL.len(), delta);
        ls.select(Some(next));
    }

    fn on_key_main(&mut self, key: &KeyEvent, sender: &EventSender) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_port_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_port_selection(1),
            KeyCode::F(5) => self.start_scan(sender),
            KeyCode::F(6) => self.stop_scan(),
            KeyCode::F(9) => self.state.popup = SettingsPopup::Menu,
            _ => {}
        }
    }

    fn on_key_menu(&mut self, key: &KeyEvent) {
        match key.code {
            KeyCode::Esc => self.state.popup = SettingsPopup::Closed,
            KeyCode::Up | KeyCode::Char('k') => self.move_menu_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_menu_selection(1),
            KeyCode::Enter => {
                let selected = self
                    .state
                    .settings_list_state
                    .borrow()
                    .selected()
                    .unwrap_or(0)
                    .min(ActiveSetting::ALL.len() - 1);
                let setting = ActiveSetting::ALL[selected];

                self.state.input_buff = setting.raw_value(&self.state);
                self.state.validation_error.clear();
                self.state.popup = SettingsPopup::Editing(setting);
            }
            _ => {}
        }
    }

    fn on_key_editing(&mut self, setting: ActiveSetting, key: &KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.state.validation_error.clear();
                self.state.popup = SettingsPopup::Menu;
            }
            KeyCode::Backspace => {
                self.state.input_buff.pop();
                self.state.validation_error.clear();
            }
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                if self.state.input_buff.chars().count() < MAX_INPUT_LEN {
                    self.state.input_buff.push(c);
                }
                self.state.validation_error.clear();
            }
            KeyCode::Enter => match self.apply_setting(setting) {
                Ok(()) => {
                    self.state.validation_error.clear();
                    self.state.popup = SettingsPopup::Menu;
                }
                Err(msg) => self.state.validation_error = msg.to_string(),
            },
            _ => {}
        }
    }

    fn apply_setting(&mut self, setting: ActiveSetting) -> Result<(), &'static str> {
        let input = self.state.input_buff.trim();

        match setting {
            ActiveSetting::TargetIp => {
                self.state.ip_address =
                    input.parse::<IpAddr>().map_err(|_| "Invalid IP address")?;
            }
            ActiveSetting::PortRange => {
                let end = input
                    .parse::<u16>()
                    .ok()
                    .filter(|&n| n >= 1)
                    .ok_or("Enter an integer from 1 to 65535")?;
                self.state.range = ..=end;
            }
            ActiveSetting::ScanSpeed => {
                self.state.max_speed = input
                    .parse::<u16>()
                    .ok()
                    .filter(|&n| n >= 1)
                    .ok_or("Enter an integer from 1 to 65535")?;
            }
            ActiveSetting::BufferCapacity => {
                self.state.max_cap = input
                    .parse::<usize>()
                    .ok()
                    .filter(|&n| n >= 1)
                    .ok_or("Enter an integer of at least 1")?;
                self.trim_ports();
            }
        }
        Ok(())
    }

    // ───────────── rendering ─────────────

    fn render_config(&self, frame: &mut Frame, area: Rect) {
        let lines = vec![
            Line::from(format!("TARGET_NETNODE: {}", self.state.ip_address)),
            Line::from(format!("TARGET_PORTS: 1..{}", self.state.range.end)),
            Line::from(format!("SCAN_SPEED: {}", self.state.max_speed)),
            Line::from(format!("MAX PORT CAPACITY: {}", self.state.max_cap)),
        ];

        let widget = Paragraph::new(lines)
            .style(Style::new().fg(Color::Cyan))
            .block(
                Block::bordered()
                    .title(" [ TARGET CONFIG ] ")
                    .border_type(BorderType::Rounded)
                    .border_style(Style::new().fg(Color::DarkGray)),
            );

        frame.render_widget(widget, area);
    }

    fn render_traffic(&self, frame: &mut Frame, area: Rect) {
        let block = Block::bordered()
            .title(" [ LIVE TRAFFIC SPARKLINE ] ")
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(Color::DarkGray));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let [gauge_row, probe_row, spark_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .areas(inner);

        let [label_area, bar_area] =
            Layout::horizontal([Constraint::Length(13), Constraint::Min(0)]).areas(gauge_row);

        let current_speed = self.state.traffic_history.last().copied().unwrap_or(0);
        frame.render_widget(
            Paragraph::new(format!("Pkts/s: {current_speed:<3} "))
                .style(Style::new().fg(Color::White)),
            label_area,
        );

        let gauge = Gauge::default()
            .percent(self.state.scan_progress.min(100))
            .gauge_style(Style::default().fg(Color::Magenta).bg(Color::Indexed(236)))
            .use_unicode(false)
            .label(format!("{}%", self.state.scan_progress));
        frame.render_widget(gauge, bar_area);

        frame.render_widget(
            Paragraph::new(format!("Curr: {}", self.state.current_probe))
                .style(Style::new().fg(Color::DarkGray)),
            probe_row,
        );

        let sparkline = Sparkline::default()
            .data(&self.state.traffic_history)
            .max(250)
            .style(Style::default().fg(Color::Green));
        frame.render_widget(sparkline, spark_area);
    }

    fn render_ports(&self, frame: &mut Frame, area: Rect) {
        if self.state.ports.is_empty() {
            frame.render_widget(
                Block::bordered()
                    .title(" ❖ [ STREAM OVERRIDE REQUIRED ] ❖ ")
                    .border_type(BorderType::Rounded)
                    .border_style(Style::new().fg(Color::Red)),
                area,
            );
            return;
        }

        let items: Vec<ListItem> = self.state.ports.iter().map(port_to_item).collect();

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
        frame.render_stateful_widget(list, area, &mut *list_state);

        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("▓"))
            .end_symbol(Some("░"))
            .track_symbol(Some("│"))
            .thumb_symbol("█");

        let mut scrollbar_state = ScrollbarState::new(self.state.ports.len())
            .position(list_state.selected().unwrap_or(0));

        frame.render_stateful_widget(
            scrollbar,
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }

    fn render_popup(&self, frame: &mut Frame) {
        let screen = frame.area();

        match self.state.popup {
            SettingsPopup::Closed => {}

            SettingsPopup::Menu => {
                let height = ActiveSetting::ALL.len() as u16 + 2;
                let popup_area = centered_rect(screen, POPUP_WIDTH, height);

                let selected = self
                    .state
                    .settings_list_state
                    .borrow()
                    .selected()
                    .unwrap_or(0);

                let items: Vec<ListItem> = ActiveSetting::ALL
                    .iter()
                    .enumerate()
                    .map(|(i, setting)| ListItem::new(setting.to_line(&self.state, i == selected)))
                    .collect();

                let list = List::new(items)
                    .block(Block::bordered().title(format!(
                        " Settings ({}/{}) ",
                        selected + 1,
                        ActiveSetting::ALL.len()
                    )))
                    .highlight_style(Style::default().add_modifier(Modifier::BOLD));

                frame.render_widget(Clear, popup_area);
                frame.render_stateful_widget(
                    list,
                    popup_area,
                    &mut *self.state.settings_list_state.borrow_mut(),
                );
            }

            SettingsPopup::Editing(setting) => {
                let popup_area = centered_rect(screen, POPUP_WIDTH, 6);

                let has_error = !self.state.validation_error.is_empty();
                let color = if has_error { Color::Red } else { Color::Yellow };

                let header = if has_error {
                    format!("[ERR]: {}", self.state.validation_error)
                } else {
                    setting.prompt().to_string()
                };

                let text = vec![
                    Line::from(Span::styled(
                        header,
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                    Line::from(format!("  NET_CMD > {}_", self.state.input_buff)),
                    Line::from(Span::styled(
                        "  [Enter] apply   [Esc] back",
                        Style::default().fg(Color::DarkGray),
                    )),
                ];

                let widget = Paragraph::new(text).block(
                    Block::bordered()
                        .title(" [ SETTINGS_CONFIG ] ")
                        .border_type(BorderType::Double)
                        .border_style(Style::default().fg(color)),
                );

                frame.render_widget(Clear, popup_area);
                frame.render_widget(widget, popup_area);
            }
        }
    }
}

fn port_to_item(port: &Port) -> ListItem<'static> {
    let dim = Style::default().fg(Color::DarkGray);

    let (state_label, state_color, glyph) = match port.state {
        PortState::Open => ("  [ONLINE]  ", Color::Magenta, "⚡"),
        PortState::Filtered => (" [Filtered]  ", Color::Yellow, "🔒"),
        PortState::Closed => (" [OFFLINE]  ", Color::DarkGray, "✖"),
    };

    let conn_color = match port.conn_type {
        ConnType::Tcp => Color::Green,
        ConnType::Udp => Color::Cyan,
    };

    let mut spans = vec![
        Span::styled(format!("// SYS_NET {glyph} ── "), dim),
        Span::styled(
            format!("PORT 0x{:04X} ", port.port),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("({}) ", port.port),
            Style::default().fg(Color::White),
        ),
        Span::styled("── ", dim),
        Span::styled(
            format!("[{}] ", port.conn_type.as_str()),
            Style::default().fg(conn_color),
        ),
        Span::styled("── ", dim),
        Span::styled(
            state_label,
            Style::default()
                .fg(state_color)
                .add_modifier(Modifier::BOLD),
        ),
    ];

    if port.state == PortState::Open {
        spans.push(Span::styled("── ", dim));
        spans.push(Span::styled(
            format!("srv: [{}] ", port.service),
            Style::default().fg(Color::LightGreen),
        ));

        if !matches!(port.banner.as_str(), "" | "-" | "No banner") {
            spans.push(Span::styled(
                format!("📡 sig: \"{}\"", port.banner),
                Style::default().fg(Color::Indexed(244)),
            ));
        }
    }

    ListItem::new(Line::from(spans))
}

// ───────────────────────────── AppMod ─────────────────────────────

impl AppMod for PortsContent {
    fn render(&self, frame: &mut Frame, area: Rect, _app: &App) {
        let (title, title_color) = match self.state.scan_state {
            ScanLabelStatus::Waiting => (" [ SYSTEM IDLE: PORTS ] ", Color::Cyan),
            ScanLabelStatus::Scanning => (" [ BREACH IN PROGRESS: SCANNING... ] ", Color::Magenta),
            ScanLabelStatus::Finished => (" [ DATA EXTRACTION FINISHED ] ", Color::Green),
        };

        let outer = Block::bordered()
            .title(title)
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(title_color));
        let inner = outer.inner(area);
        frame.render_widget(outer, area);

        let [top, bottom] =
            Layout::vertical([Constraint::Percentage(30), Constraint::Percentage(70)]).areas(inner);
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(top);

        self.render_config(frame, left);
        self.render_traffic(frame, right);
        self.render_ports(frame, bottom);
        self.render_popup(frame);
    }

    fn on_key(&mut self, key: &KeyEvent, sender: &EventSender) {
        match self.state.popup {
            SettingsPopup::Closed => self.on_key_main(key, sender),
            SettingsPopup::Menu => self.on_key_menu(key),
            SettingsPopup::Editing(setting) => self.on_key_editing(setting, key),
        }
    }

    fn update(&mut self, event: &Event, _sender: &EventSender) {
        if let Some(ev) = event.downcast_ref::<ScanEvent>() {
            self.on_scan_event(ev);
        }
    }

    fn instructions(&self) -> Vec<String> {
        let mut keys = vec!["[F5: Scan]".to_string()];
        if self.state.scan_state == ScanLabelStatus::Scanning {
            keys.push("[F6: Stop]".to_string());
        }
        keys.push("[F9: Settings]".to_string());
        keys
    }

    fn captures_input(&self) -> bool {
        self.state.popup != SettingsPopup::Closed
    }
}
