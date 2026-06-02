use std::io::stderr;

use crate::app::App;
use crate::events::{Event, EventHandler};
use crate::ui::contents::main_content::MainContent;
use crate::ui::contents::scan_ports::{self, ConnType, Port};
use anyhow::Result;
use ratatui::crossterm::ExecutableCommand;
use ratatui::crossterm::terminal;

mod app;
mod events;
mod ui;

#[tokio::main]
async fn main() -> Result<()> {
    stderr().execute(terminal::EnterAlternateScreen)?;
    terminal::enable_raw_mode()?;

    let backend = ratatui::backend::CrosstermBackend::new(stderr());
    let mut terminal = ratatui::Terminal::new(backend)?;
    let mut events_handler = EventHandler::new(250);

    let ports = vec![
        Port::new(16, ConnType::Tcp),
        Port::new(13, ConnType::Tcp),
        Port::new(12, ConnType::Tcp),
    ];
    let ports_content = scan_ports::PortsContent::new(ports);
    let main_content = MainContent {
        content: String::new(),
    };
    let mut app = App::new(vec![Box::new(main_content), Box::new(ports_content)]);

    loop {
        terminal
            .draw(|frame| ui::render::render_ui(frame, &app))
            .expect("cant render ui");

        match events_handler.next().await.expect("Unable to read events") {
            Event::Tick => {}
            Event::Key(k) => {
                use ratatui::crossterm::event::KeyCode;

                app.current_page_mut().controls(k.code);
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
        }

        if app.exit {
            break;
        }
    }

    stderr().execute(terminal::LeaveAlternateScreen)?;
    terminal::disable_raw_mode()?;

    Ok(())
}
