use ratatui::crossterm::event::KeyCode;

pub trait InputBlock {
    fn control(&mut self, key: KeyCode);
}
