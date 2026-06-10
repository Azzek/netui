use tokio::sync::mpsc::Sender;

use crate::{app::App, events::Event};

pub trait Content {
    fn update(&mut self, event: Event, tx: Sender<Event>);
    fn render(&self, f: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &App);
    fn captures_input(&self) -> bool {
        false
    }
    fn instructions(&self) -> Vec<String>;
}
