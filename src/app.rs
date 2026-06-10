use ratatui::crossterm::event::KeyCode;
use tokio::sync::mpsc::Sender; // Potrzebne do przekazania kanału

use crate::{events::Event, ui::contents::content::Content};

pub struct App {
    pub exit: bool,
    pub content: String,
    pub pages: Vec<Box<dyn Content>>,
    pub current_page: usize,
    pub popup: Option<String>,
}

impl App {
    pub fn new(pages: Vec<Box<dyn Content>>) -> Self {
        Self {
            exit: false,
            content: String::new(),
            pages,
            current_page: 0,
            popup: None,
        }
    }

    pub fn handle_events(&mut self, event: Event, tx: Sender<Event>) {
        let mut forward_key_to_page = true;
        if !self.current_page().captures_input() {
            match &event {
                Event::Key(k) => {
                    if self.popup.is_some() {
                        forward_key_to_page = false;
                        if k.code == KeyCode::Esc {
                            self.popup = None;
                        }
                    } else {
                        match k.code {
                            KeyCode::Char('1') => self.navigate(0),
                            KeyCode::Char('2') => self.navigate(1),
                            KeyCode::Char('q') => self.exit = true,
                            KeyCode::Backspace => {
                                self.content.pop();
                            }
                            KeyCode::Char(c) => self.content.push(c),
                            _ => {}
                        }
                    }
                }
                Event::Popup(txt) => {
                    self.popup = Some(txt.clone());
                }
                Event::Tick => {}
                _ => {}
            }
        }

        if forward_key_to_page || !matches!(event, Event::Key(_)) {
            self.current_page_mut().update(event, tx);
        }
    }

    pub fn current_page(&self) -> &dyn Content {
        self.pages[self.current_page].as_ref()
    }

    pub fn current_page_mut(&mut self) -> &mut dyn Content {
        self.pages[self.current_page].as_mut()
    }

    pub fn navigate(&mut self, index: usize) {
        if index < self.pages.len() {
            self.current_page = index;
        }
    }
}
