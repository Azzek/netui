use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::Text,
    widgets::{Block, Paragraph, Widget},
};

pub struct Popup {
    text: String,
}

impl Popup {
    pub fn new(text: String) -> Self {
        Self { text }
    }
}

impl Widget for Popup {
    fn render(self, rect: Rect, buff: &mut Buffer) {
        let popup_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(25),
                Constraint::Percentage(50),
                Constraint::Percentage(25),
            ])
            .split(rect);

        let popup_rect = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(25),
                Constraint::Percentage(50),
                Constraint::Percentage(25),
            ])
            .split(popup_layout[1])[1];

        let popup = Paragraph::new(Text::raw(self.text)).centered().block(
            Block::bordered()
                .title("Info")
                .border_style(Style::new().green()),
        );
        popup.render(popup_rect, buff);
    }
}
