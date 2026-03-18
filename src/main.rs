use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use openssl::symm::{encrypt_aead, Cipher};
use rand::RngCore;
use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

const VERSION: u8 = 1;
const STREAM_VIDEO: u8 = 1;
const STREAM_AUDIO: u8 = 2;

const HEADER_SIZE: usize = 1 + 1 + 4 + 2 + 2 + 8 + 12;
const MAX_UDP_PAYLOAD: usize = 1200;
const TAG_SIZE: usize = 16;
const MAX_PLAINTEXT_CHUNK: usize = MAX_UDP_PAYLOAD - HEADER_SIZE - TAG_SIZE;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, value_enum)]
    stream: StreamKind,

    #[arg(long, value_enum, default_value = "openssl")]
    backend: Backend,

    #[arg(long)]
    key_hex: String,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum StreamKind {
    Video,
    Audio,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Backend {
    Openssl,
    Rustcrypto,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let key = hex::decode(&args.key_hex).context("invalid --key-hex")?;
    if key.len() != 32 {
        bail!("key must be 32 bytes / 64 hex chars");
    }

    let stream_type = match args.stream {
        StreamKind::Video => STREAM_VIDEO,
        StreamKind::Audio => STREAM_AUDIO,
    };

    let stdin = io::stdin();
    let stdout = io::stdout();

    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    loop {
        let frame_id = match read_u32_be(&mut reader) {
            Ok(v) => v,
            Err(_) => break, // clean EOF
        };

        let payload_len = read_u32_be(&mut reader)? as usize;
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload)?;

        let packets = build_packets(&key, stream_type, frame_id, &payload, args.backend)?;

        write_u32_be(&mut writer, packets.len() as u32)?;
        for pkt in packets {
            write_u32_be(&mut writer, pkt.len() as u32)?;
            writer.write_all(&pkt)?;
        }
        writer.flush()?;
    }

    Ok(())
}

fn build_packets(
    key: &[u8],
    stream_type: u8,
    frame_id: u32,
    payload: &[u8],
    backend: Backend,
) -> Result<Vec<Vec<u8>>> {
    let timestamp_ms = now_ms();
    let chunk_count = ((payload.len() + MAX_PLAINTEXT_CHUNK - 1) / MAX_PLAINTEXT_CHUNK) as u16;

    let mut packets = Vec::with_capacity(chunk_count as usize);

    for chunk_index in 0..chunk_count {
        let start = chunk_index as usize * MAX_PLAINTEXT_CHUNK;
        let end = usize::min(start + MAX_PLAINTEXT_CHUNK, payload.len());
        let chunk_plain = &payload[start..end];

        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        let header = build_header(
            VERSION,
            stream_type,
            frame_id,
            chunk_index,
            chunk_count,
            timestamp_ms,
            &nonce,
        );

        let mut ciphertext_and_tag = match backend {
            Backend::Openssl => encrypt_openssl(key, &nonce, &header, chunk_plain)?,
            Backend::Rustcrypto => encrypt_rustcrypto(key, &nonce, &header, chunk_plain)?,
        };

        let mut packet = Vec::with_capacity(header.len() + ciphertext_and_tag.len());
        packet.extend_from_slice(&header);
        packet.append(&mut ciphertext_and_tag);
        packets.push(packet);
    }

    Ok(packets)
}

fn encrypt_openssl(key: &[u8], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut tag = [0u8; TAG_SIZE];
    let ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        key,
        Some(nonce),
        aad,
        plaintext,
        &mut tag,
    )?;

    let mut out = Vec::with_capacity(ciphertext.len() + TAG_SIZE);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out)
}

fn encrypt_rustcrypto(key: &[u8], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let nonce = Nonce::from_slice(nonce);

    let out = cipher.encrypt(
        nonce,
        Payload {
            msg: plaintext,
            aad,
        },
    )?;
    Ok(out)
}

fn build_header(
    version: u8,
    stream_type: u8,
    frame_id: u32,
    chunk_index: u16,
    chunk_count: u16,
    timestamp_ms: u64,
    nonce: &[u8; 12],
) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_SIZE);
    h.push(version);
    h.push(stream_type);
    h.extend_from_slice(&frame_id.to_be_bytes());
    h.extend_from_slice(&chunk_index.to_be_bytes());
    h.extend_from_slice(&chunk_count.to_be_bytes());
    h.extend_from_slice(&timestamp_ms.to_be_bytes());
    h.extend_from_slice(nonce);
    h
}

fn read_u32_be<R: Read>(r: &mut R) -> Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

fn write_u32_be<W: Write>(w: &mut W, v: u32) -> Result<()> {
    w.write_all(&v.to_be_bytes())?;
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}