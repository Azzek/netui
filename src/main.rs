use std::io::stderr;

use anyhow::Result;
use ratatui::crossterm::{ExecutableCommand, terminal};

use crate::events::EventHandler;

mod app;
mod events;
mod features;
mod mods;
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

    let ports_mod = mods::scan_ports::PortsContent::new();
    let main_mod = mods::main_content::MainContent {
        content: String::new(),
    };
    let sniff_mod = mods::packet_sniffer::SnifferMod::new();
    let mut app = app::App::new(vec![
        Box::new(main_mod),
        Box::new(ports_mod),
        Box::new(sniff_mod),
    ]);
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
