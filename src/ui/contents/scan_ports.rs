use ratatui::{
    Frame,
    crossterm::event::KeyCode,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Text},
    widgets::{Block, BorderType, Paragraph, Widget},
};

use crate::{app::App, ui::contents::content::Content};

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
    Quic,
}

impl ConnType {
    pub fn as_str(&self) -> &str {
        match self {
            ConnType::Udp => "UDP",
            ConnType::Tcp => "TCP",
            ConnType::Quic => "QUIC",
        }
    }
}

pub struct Button {
    text: String,
    is_hovered: bool,
}

impl Button {
    pub fn new(text: String) -> Self {
        Self {
            text,
            is_hovered: false,
        }
    }
}

pub struct PortsContent {
    pub ports: Vec<Port>,
    buttons: Vec<Button>,
}

impl PortsContent {
    pub fn new(ports: Vec<Port>) -> Self {
        let mut buttons = vec![
            Button::new("Scan".to_string()),
            Button::new("Stop".to_string()),
        ];

        buttons[0].is_hovered = true;
        Self { ports, buttons }
    }
}

impl Content for PortsContent {
    fn render(&self, frame: &mut Frame, area: Rect, app: &App) {
        let buf = frame.buffer_mut();

        let layout =
            Layout::vertical([Constraint::Percentage(80), Constraint::Percentage(20)]).split(area);

        let outer = Block::bordered()
            .title(" Ports ")
            .border_type(BorderType::Rounded)
            .border_style(Style::new().blue());

        let inner_area = outer.inner(layout[0]);
        outer.render(layout[0], buf);

        if !self.ports.is_empty() {
            let constraints: Vec<Constraint> =
                self.ports.iter().map(|_| Constraint::Length(1)).collect();

            let rows = Layout::vertical(constraints).split(inner_area);

            for (port, row_area) in self.ports.iter().zip(rows.iter()) {
                let line = Line::raw(format!("{:>5}  {}", port.port, port.conn_type.as_str()));
                Paragraph::new(line).render(*row_area, buf);
            }
        }

        if self.buttons.is_empty() {
            return;
        }

        let btn_constraints: Vec<Constraint> =
            self.buttons.iter().map(|_| Constraint::Fill(1)).collect();

        let btn_areas = Layout::horizontal(btn_constraints).split(layout[1]);

        for (btn, btn_area) in self.buttons.iter().zip(btn_areas.iter()) {
            let style = if !btn.is_hovered {
                Style::default()
                    .fg(Color::Yellow)
                    .bg(Color::Reset)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Blue)
            };

            let pbtn = Paragraph::new(Text::raw(btn.text.as_str()))
                .block(
                    Block::bordered()
                        .border_style(style)
                        .title(btn.text.as_str()),
                )
                .style(style);

            pbtn.render(*btn_area, buf);
        }
    }

    fn controls(&mut self, key: KeyCode) {
        if self.buttons.is_empty() {
            return;
        }

        if let Some(hover_index) = self.buttons.iter().position(|b| b.is_hovered) {
            match key {
                KeyCode::Right => {
                    let new_hover_index = (hover_index + 1) % self.buttons.len();
                    self.buttons[hover_index].is_hovered = false;
                    self.buttons[new_hover_index].is_hovered = true;
                }
                KeyCode::Left => {
                    let new_hover_index = if hover_index == 0 {
                        self.buttons.len() - 1
                    } else {
                        hover_index - 1
                    };
                    self.buttons[hover_index].is_hovered = false;
                    self.buttons[new_hover_index].is_hovered = true;
                }
                _ => {}
            }
        }
    }
}
