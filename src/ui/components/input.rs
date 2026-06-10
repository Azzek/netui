use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::Text,
    widgets::{Block, Paragraph, Widget},
};

use crate::traits::InputBlock;

pub struct Input {
    input_buff: String,
}

impl InputBlock for Input {
    fn control(&mut self, key: ratatui::crossterm::event::KeyCode) {
        if let Some(char) = key.as_char() {
            self.input_buff.push(char);
        }
    }
}

impl Widget for Input {
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

        let popup = Paragraph::new(Text::raw(self.input_buff)).centered().block(
            Block::bordered()
                .title("Info")
                .border_style(Style::new().green()),
        );
        popup.render(popup_rect, buff);
    }
}
