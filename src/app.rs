use crate::ui::contents::content::Content;

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
