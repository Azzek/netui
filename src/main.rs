use std::io::stderr;

use crate::app::App;
use crate::events::{Event, EventHandler};
use crate::ui::contents::main_content::MainContent;
use crate::ui::contents::scan_ports;
use anyhow::Result;
use ratatui::crossterm::ExecutableCommand;
use ratatui::crossterm::event::KeyCode;
use ratatui::crossterm::terminal;

mod app;
mod events;
mod features;
mod ui;

#[tokio::main]
async fn main() -> Result<()> {
    stderr().execute(terminal::EnterAlternateScreen)?;
    terminal::enable_raw_mode()?;

    let backend = ratatui::backend::CrosstermBackend::new(stderr());
    let mut terminal = ratatui::Terminal::new(backend)?;
    let mut events_handler = EventHandler::new(250);

    let ports_content = scan_ports::PortsContent::new();
    let main_content = MainContent {
        content: String::new(),
    };
    let mut app = App::new(vec![Box::new(main_content), Box::new(ports_content)]);

    app.popup = Some("welcome in app!".to_string());
    loop {
        terminal
            .draw(|frame| ui::render::render_ui(frame, &app))
            .expect("cant render ui");

        let event = events_handler.next().await.expect("Unable to read events");

        // main event controlling
        match &event {
            Event::Tick => {}
            Event::Key(k) => {
                if app.popup.is_some() {
                    if k.code != KeyCode::Esc {
                        continue;
                    }
                    app.popup = None;
                }
                match k.code {
                    KeyCode::Char('1') => app.navigate(0),
                    KeyCode::Char('2') => app.navigate(1),
                    KeyCode::Char('q') => break,
                    KeyCode::Backspace => {
                        app.content.pop();
                    }
                    KeyCode::Char(c) => app.content.push(c),
                    _ => {}
                }
            }
            Event::Popup(txt) => {
                app.popup = Some(txt.clone());
            }
            _ => {}
        }

        // Current page event controlling
        app.current_page_mut()
            .update(event, events_handler.sender.clone());

        if app.exit {
            break;
        }
    }

    stderr().execute(terminal::LeaveAlternateScreen)?;
    terminal::disable_raw_mode()?;

    Ok(())
}
