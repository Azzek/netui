use std::net::IpAddr;
use std::ops::RangeToInclusive;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::events::Event;
use crate::mods::scan_ports::{ConnType, Port};

fn lookup_service(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        443 => "https",
        8080 => "http-proxy",
        _ => "unknown",
    }
}

pub fn launch_background_scan(
    target_ip: IpAddr,
    tx: Sender<Event>,
    range: RangeToInclusive<u16>,
    max_workers: u16,
) {
    tokio::spawn(async move {
        let mut set = JoinSet::new();

        let mut ports_range = 1..range.end;
        let total_ports = ports_range.end;
        let mut processed_ports = 0;
        let mut pkts_this_second = 0;
        let mut current_pkts_s = 0;
        let mut last_tick = Instant::now();

        for _ in 0..max_workers {
            if let Some(port) = ports_range.next() {
                set.spawn(async move { scan_tcp(target_ip, port).await });
            }
        }

        while let Some(result) = set.join_next().await {
            processed_ports += 1;
            pkts_this_second += 1;

            if let Some(next_port) = ports_range.next() {
                set.spawn(async move { scan_tcp(target_ip, next_port).await });
            }

            if last_tick.elapsed() >= Duration::from_secs(1) {
                current_pkts_s = pkts_this_second;
                pkts_this_second = 0;
                last_tick = Instant::now();
            }

            if let Ok((port_num, scan_result)) = result {
                if let Ok(port_data) = scan_result {
                    let _ = tx.send(Event::PortFound(port_data)).await;
                };

                let progress = ((processed_ports as u64 * 100) / total_ports as u64) as u32;
                let current_probe = format!("TCP/SYN -> {}:{}", target_ip, port_num);
                let _ = tx
                    .send(Event::ScanProgress {
                        progress,
                        current_probe,
                        pkts_s: current_pkts_s,
                    })
                    .await;
            }
        }

        let _ = tx.send(Event::ScanFinished).await;
    });
}

async fn scan_tcp(ip: IpAddr, port: u16) -> (u16, Result<Port, Port>) {
    let addr = std::net::SocketAddr::new(ip, port);

    let connection_result = timeout(Duration::from_millis(800), TcpStream::connect(&addr)).await;

    match connection_result {
        Err(_) => (
            port,
            Err(Port {
                port,
                state: "Filtered".to_string(),
                service: lookup_service(port).to_string(),
                banner: "No response (Firewall)".to_string(),
                conn_type: ConnType::Tcp,
            }),
        ),

        Ok(Err(ref e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => (
            port,
            Ok(Port {
                port,
                state: "Closed".to_string(),
                service: lookup_service(port).to_string(),
                banner: "-".to_string(),
                conn_type: ConnType::Tcp,
            }),
        ),

        Ok(Err(_)) => (
            port,
            Ok(Port {
                port,
                state: "Closed".to_string(),
                service: lookup_service(port).to_string(),
                banner: "-".to_string(),
                conn_type: ConnType::Tcp,
            }),
        ),

        Ok(Ok(mut stream)) => {
            let mut buffer = [0; 256];
            let service_name = lookup_service(port).to_string();
            let mut banner = "No banner".to_string();

            if port == 80 || port == 8080 {
                let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
            }

            if let Ok(Ok(bytes_read)) =
                timeout(Duration::from_millis(300), stream.read(&mut buffer)).await
            {
                if bytes_read > 0 {
                    let raw_banner = String::from_utf8_lossy(&buffer[..bytes_read]);

                    banner = raw_banner.lines().next().unwrap_or("").trim().to_string();

                    if let Some(pos) = banner.to_lowercase().find("server:") {
                        banner = banner[pos + 7..].trim().to_string();
                    }
                }
            }

            (
                port,
                Ok(Port {
                    port,
                    state: "Open".to_string(),
                    service: service_name,
                    banner,
                    conn_type: ConnType::Tcp,
                }),
            )
        }
    }
}
