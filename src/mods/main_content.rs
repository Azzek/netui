use ratatui::{
    crossterm::event::KeyEvent,
    style::Style,
    widgets::{Block, Paragraph},
};

use crate::{
    app::App,
    events::{Event, EventSender},
    traits::AppMod,
};

pub struct MainContent {
    pub content: String,
}

impl AppMod for MainContent {
    fn render(&self, f: &mut ratatui::Frame, area: ratatui::layout::Rect, _: &App) {
        let paragraph = Paragraph::new("Main Pagge")
            .block(Block::bordered().title("Main page"))
            .style(Style::default().blue());
        f.render_widget(paragraph, area);
    }

    fn update(&mut self, event: &Event, _: &EventSender) {
        match event {
            Event::Key(k) => {
                if let Some(c) = k.code.as_char() {
                    self.content.push(c);
                }
            }
            _ => {}
        }
    }
    fn on_key(&mut self, key: &KeyEvent, _sender: &EventSender) {}
    fn instructions(&self) -> Vec<String> {
        Vec::from(["noting".to_string()])
    }
}
