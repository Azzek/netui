use ratatui::crossterm::{
    self,
    event::{Event as CrosstermEvent, KeyEventKind},
};
use std::time::Duration;
use tokio::{sync::mpsc, time::Instant};

use crate::ui::contents::scan_ports::Port;

#[derive(Debug)]
pub enum Event {
    Tick,
    Key(crossterm::event::KeyEvent),
    Popup(String),
    PortFound(Port),
    CurrentPort(u16),
    ScanFinished,
    ScanProgress {
        progress: u32,
        current_probe: String,
        pkts_s: u64,
    },
}

pub struct EventHandler {
    receiver: mpsc::Receiver<Event>,
    pub sender: mpsc::Sender<Event>,
}

impl EventHandler {
    pub fn new(tick_rate: u64) -> Self {
        let tick_rate = Duration::from_millis(tick_rate);
        let (sender, receiver) = mpsc::channel(32);

        let loop_sender = sender.clone();

        tokio::spawn(async move {
            let mut last_tick = Instant::now();

            loop {
                let timeout = tick_rate
                    .checked_sub(last_tick.elapsed())
                    .unwrap_or(Duration::ZERO);

                let has_event = tokio::task::spawn_blocking(move || {
                    crossterm::event::poll(timeout).expect("Nie można sprawdzić zdarzeń.")
                })
                .await
                .expect("spawn_blocking nie powiódł się.");

                if has_event {
                    let event = tokio::task::spawn_blocking(|| {
                        crossterm::event::read().expect("Nie można odczytać zdarzenia.")
                    })
                    .await
                    .expect("spawn_blocking nie powiódł się.");

                    if let CrosstermEvent::Key(key) = event {
                        if key.kind == KeyEventKind::Press {
                            if loop_sender.send(Event::Key(key)).await.is_err() {
                                break;
                            }
                        }
                    }
                }

                if last_tick.elapsed() >= tick_rate {
                    if loop_sender.send(Event::Tick).await.is_err() {
                        break;
                    }
                    last_tick = Instant::now();
                }
            }
        });

        Self { receiver, sender }
    }

    pub async fn next(&mut self) -> Option<Event> {
        self.receiver.recv().await
    }
}
