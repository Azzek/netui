use ratatui::{
    style::Style,
    widgets::{Block, Paragraph},
};

use crate::{app::App, ui::contents::content::Content};

pub struct MainContent {
    pub content: String,
}

impl Content for MainContent {
    fn render(&self, f: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &App) {
        let paragraph = Paragraph::new("Main Pagge")
            .block(Block::bordered().title("Main page"))
            .style(Style::default().blue());
        f.render_widget(paragraph, area);
    }

    fn controls(&mut self, key: ratatui::crossterm::event::KeyCode) {
        if let Some(c) = key.as_char() {
            self.content.push(c);
        }
    }
}
