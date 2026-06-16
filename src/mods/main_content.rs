use ratatui::{
    style::Style,
    widgets::{Block, Paragraph},
};
use tokio::sync::mpsc::Sender;

use crate::{app::App, events::Event, traits::AppMod};

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

    fn update(&mut self, event: Event, _: Sender<Event>) {
        match event {
            Event::Key(k) => {
                if let Some(c) = k.code.as_char() {
                    self.content.push(c);
                }
            }
            _ => {}
        }
    }

    fn instructions(&self) -> Vec<String> {
        Vec::from(["noting".to_string()])
    }
}
