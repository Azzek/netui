use std::any::Any;
use std::fmt;
use std::time::Duration;

use ratatui::crossterm::{
    self,
    event::{Event as CrosstermEvent, KeyEvent, KeyEventKind},
};
use tokio::{sync::mpsc, time::Instant};

/// Channel capacity. The sniffer can produce a lot of events,
/// so the buffer is larger than 32.
const CHANNEL_CAPACITY: usize = 1024;

/// Core application event. Contains only global things.
/// Module events (ScanEvent, SnifferEvent, ...) are wrapped in `Mod`.
pub enum Event {
    Tick,
    Key(KeyEvent),
    Popup(String),
    Mod(Box<dyn Any + Send>),
}

impl Event {
    /// Wraps any module event type in `Event::Mod`.
    pub fn custom<T: Any + Send>(ev: T) -> Self {
        Event::Mod(Box::new(ev))
    }

    /// Returns `Some(&T)` if this is a module event of type `T`, otherwise `None`.
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        match self {
            Event::Mod(payload) => payload.as_ref().downcast_ref::<T>(),
            _ => None,
        }
    }

    /// Checks whether this is a module event of type `T`.
    pub fn is<T: Any>(&self) -> bool {
        self.downcast_ref::<T>().is_some()
    }
}

// `Box<dyn Any>` does not implement Debug, so we do it manually.
impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Tick => write!(f, "Tick"),
            Event::Key(k) => write!(f, "Key({:?})", k),
            Event::Popup(s) => write!(f, "Popup({:?})", s),
            Event::Mod(_) => write!(f, "Mod(..)"),
        }
    }
}

/// Sender wrapper that modules clone and use to send their own events.
#[derive(Clone)]
pub struct EventSender(mpsc::Sender<Event>);

impl EventSender {
    /// Sends a module event (with backpressure). Returns `false` if the receiver is gone.
    pub async fn send<T: Any + Send>(&self, ev: T) -> bool {
        self.0.send(Event::custom(ev)).await.is_ok()
    }

    /// Sends a module event without waiting. Returns `false` if the channel is full or closed.
    /// Good for hot paths (e.g. the sniffer), where dropping an event beats blocking.
    pub fn try_send<T: Any + Send>(&self, ev: T) -> bool {
        self.0.try_send(Event::custom(ev)).is_ok()
    }

    /// Sends a core event (Popup, etc.).
    pub async fn send_core(&self, ev: Event) -> bool {
        self.0.send(ev).await.is_ok()
    }

    pub fn blocking_send_core(&self, ev: Event) -> bool {
        self.0.blocking_send(ev).is_ok()
    }

    // Sends blocking events
    pub fn blocking_send<T: Any + Send>(&self, ev: T) -> bool {
        self.0.blocking_send(Event::custom(ev)).is_ok()
    }

    /// Shortcut for showing a popup.
    pub async fn popup(&self, msg: impl Into<String>) -> bool {
        self.send_core(Event::Popup(msg.into())).await
    }
}

pub struct EventHandler {
    receiver: mpsc::Receiver<Event>,
    pub sender: EventSender,
}

impl EventHandler {
    pub fn new(tick_rate: u64) -> Self {
        let tick_rate = Duration::from_millis(tick_rate);
        let (tx, receiver) = mpsc::channel(CHANNEL_CAPACITY);

        let loop_sender = tx.clone();

        tokio::spawn(async move {
            let mut last_tick = Instant::now();

            loop {
                let timeout = tick_rate
                    .checked_sub(last_tick.elapsed())
                    .unwrap_or(Duration::ZERO);

                let has_event = tokio::task::spawn_blocking(move || {
                    crossterm::event::poll(timeout).expect("Failed to poll for events.")
                })
                .await
                .expect("spawn_blocking failed.");

                if has_event {
                    let event = tokio::task::spawn_blocking(|| {
                        crossterm::event::read().expect("Failed to read event.")
                    })
                    .await
                    .expect("spawn_blocking failed.");

                    if let CrosstermEvent::Key(key) = event {
                        if key.kind == KeyEventKind::Press
                            && loop_sender.send(Event::Key(key)).await.is_err()
                        {
                            break;
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

        Self {
            receiver,
            sender: EventSender(tx),
        }
    }

    pub async fn next(&mut self) -> Option<Event> {
        self.receiver.recv().await
    }

    pub fn try_next(&mut self) -> Option<Event> {
        self.receiver.try_recv().ok()
    }
}
