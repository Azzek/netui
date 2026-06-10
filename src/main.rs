use std::io::stderr;

use anyhow::Result;
use ratatui::crossterm::{ExecutableCommand, terminal};

use crate::{
    events::EventHandler,
    ui::contents::{main_content::MainContent, scan_ports},
};

mod app;
mod events;
mod features;
mod traits;
mod ui;

#[tokio::main]
async fn main() -> Result<()> {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = stderr().execute(terminal::LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
        default_hook(panic_info);
    }));

    stderr().execute(terminal::EnterAlternateScreen)?;
    terminal::enable_raw_mode()?;

    let backend = ratatui::backend::CrosstermBackend::new(stderr());
    let mut terminal = ratatui::Terminal::new(backend)?;
    let mut events_handler = EventHandler::new(250);

    let ports_content = scan_ports::PortsContent::new();
    let main_content = MainContent {
        content: String::new(),
    };
    let mut app = app::App::new(vec![Box::new(main_content), Box::new(ports_content)]);
    app.popup = Some("Welcome to the app!".to_string());

    loop {
        terminal
            .draw(|frame| ui::render::render_ui(frame, &app))
            .expect("cant render ui");

        let event = events_handler.next().await.expect("Unable to read events");

        app.handle_events(event, events_handler.sender.clone());

        if app.exit {
            break;
        }
    }

    stderr().execute(terminal::LeaveAlternateScreen)?;
    terminal::disable_raw_mode()?;

    Ok(())
}
