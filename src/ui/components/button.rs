use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, Widget};

pub struct Button {
    pub label: String,
    pub is_focused: bool,
}

impl Button {
    pub fn new(label: String, is_focused: bool) -> Self {
        Self { label, is_focused }
    }
}

impl Widget for &Button {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let (border_color, text_color, modifier) = if self.is_focused {
            (Color::Yellow, Color::Black, Modifier::BOLD)
        } else {
            (Color::Blue, Color::Black, Modifier::BOLD)
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title_alignment(Alignment::Center);

        let text_style = Style::default()
            .bg(border_color)
            .fg(text_color)
            .add_modifier(modifier);

        let text = Line::from(self.label.to_string())
            .alignment(Alignment::Center)
            .style(text_style);

        Paragraph::new(text).block(block).render(area, buf);
    }
}
