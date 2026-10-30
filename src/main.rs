use std::io::{Stderr, stderr};

use anyhow::Result;
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    crossterm::{ExecutableCommand, terminal},
};

use crate::{app::App, events::EventHandler};

mod app;
mod events;
mod features;
mod mods;
mod traits;
mod ui;

type Term = Terminal<CrosstermBackend<Stderr>>;

fn restore_terminal() {
    let _ = stderr().execute(terminal::LeaveAlternateScreen);
    let _ = terminal::disable_raw_mode();
}

#[tokio::main]
async fn main() -> Result<()> {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        restore_terminal();
        default_hook(panic_info);
    }));

    stderr().execute(terminal::EnterAlternateScreen)?;
    terminal::enable_raw_mode()?;

    let mut terminal = Terminal::new(CrosstermBackend::new(stderr()))?;
    let mut events = EventHandler::new(250);

    let mut app = App::new(vec![
        Box::new(mods::main_content::MainContent {
            content: String::new(),
        }),
        Box::new(mods::scan_ports::PortsContent::new()),
        Box::new(mods::packet_sniffer::SnifferMod::new()),
    ]);
    app.popup = Some("Welcome to the app!".to_string());

    let result = run(&mut terminal, &mut app, &mut events).await;

    restore_terminal();
    result
}

async fn run(terminal: &mut Term, app: &mut App, events: &mut EventHandler) -> Result<()> {
    while !app.exit {
        terminal.draw(|frame| ui::render::render_ui(frame, &*app))?;

        let Some(event) = events.next().await else {
            break;
        };
        app.handle_events(&event, &events.sender);

        while !app.exit {
            let Some(event) = events.try_next() else {
                break;
            };
            app.handle_events(&event, &events.sender);
        }
    }

    Ok(())
}
