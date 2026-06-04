use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::events::Event;
use crate::ui::contents::scan_ports::{ConnType, Port};

pub fn launch_background_scan(target_ip: IpAddr, tx: Sender<Event>) {
    tokio::spawn(async move {
        let mut ports_range = 1u16..=65535;
        let mut set = JoinSet::new();

        for _ in 0..200 {
            if let Some(port) = ports_range.next() {
                set.spawn(async move { scan_tcp(target_ip, port).await });
            }
        }

        while let Some(result) = set.join_next().await {
            if let Some(next_port) = ports_range.next() {
                set.spawn(async move { scan_tcp(target_ip, next_port).await });
            }

            if let Ok(Ok(open_port)) = result {
                let _ = tx.send(Event::PortFound(open_port)).await;
            }
        }

        let _ = tx.send(Event::ScanFinished).await;
    });
}

async fn scan_tcp(ip: IpAddr, port: u16) -> Result<Port, String> {
    let addr = std::net::SocketAddr::new(ip, port);
    match timeout(Duration::from_millis(2000), TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => Ok(Port::new(port, ConnType::Tcp)),
        _ => Err("Closed/Filtered".to_string()),
    }
}
