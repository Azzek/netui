use ratatui::crossterm::event::KeyCode;
use tokio::sync::mpsc::Sender;

use crate::{app::App, events::Event};

pub trait Content {
    fn controls(&mut self, key: KeyCode, tx: &Sender<Event>);
    fn render(&self, f: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &App);
}
