use ratatui::crossterm::event::{Event::Key, KeyCode, KeyEvent};

use crate::{
    app::App,
    events::{Event, EventSender},
};

pub trait InputBlock {
    fn control(&mut self, key: KeyCode);
}

pub trait AppMod {
    fn update(&mut self, event: &Event, sender: &EventSender);
    fn render(&self, f: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &App);
    fn on_key(&mut self, key: &KeyEvent, _sender: &EventSender);
    fn captures_input(&self) -> bool {
        false
    }
    fn instructions(&self) -> Vec<String>;
}
