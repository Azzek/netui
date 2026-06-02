use ratatui::crossterm::event::KeyCode;

use crate::app::App;

pub trait Content {
    fn controls(&mut self, key: KeyCode);
    fn render(&self, f: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &App);
}
