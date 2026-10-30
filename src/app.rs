use crate::events::{Event, EventSender};
use crate::traits::AppMod;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub struct App {
    pub exit: bool,
    pub pages: Vec<Box<dyn AppMod>>,
    pub current_page: usize,
    pub popup: Option<String>,
}

impl App {
    pub fn new(pages: Vec<Box<dyn AppMod>>) -> Self {
        Self {
            exit: false,
            pages,
            current_page: 0,
            popup: None,
        }
    }

    pub fn handle_events(&mut self, event: &Event, sender: &EventSender) {
        match event {
            Event::Key(key) => self.handle_key(key, sender),
            Event::Popup(text) => self.popup = Some(text.clone()),
            _ => {
                for page in self.pages.iter_mut() {
                    page.update(event, sender);
                }
            }
        }
    }

    fn handle_key(&mut self, key: &KeyEvent, sender: &EventSender) {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.exit = true;
            return;
        }

        if self.popup.is_some() {
            if key.code == KeyCode::Esc {
                self.popup = None;
            }
            return;
        }

        if !self.current_page().captures_input() {
            match key.code {
                KeyCode::Char('q') => {
                    self.exit = true;
                    return;
                }
                KeyCode::Char(c @ '1'..='9') => {
                    self.navigate((c as u8 - b'1') as usize);
                    return;
                }
                _ => {}
            }
        }

        self.current_page_mut().on_key(key, sender);
    }

    pub fn current_page(&self) -> &dyn AppMod {
        self.pages[self.current_page].as_ref()
    }

    pub fn current_page_mut(&mut self) -> &mut dyn AppMod {
        self.pages[self.current_page].as_mut()
    }

    pub fn navigate(&mut self, index: usize) {
        if index < self.pages.len() {
            self.current_page = index;
        }
    }
}
