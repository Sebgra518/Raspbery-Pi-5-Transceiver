use anyhow::{bail, Context, Result};
use openssl::symm::{Cipher, Crypter, Mode};
use std::fs;
use std::io::{self, Read, Write};


/*
Encyrption:
    // 12-byte GCM nonce:
    // 1 byte stream type
    // 3 bytes reserved
    // 8 bytes monotonically increasing counter
*/

fn aes_gcm_encrypt(key: &[u8],nonce: &[u8; 12],aad: &[u8],plaintext: &[u8],) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(nonce))
        .context("create crypter")?;

    crypter.aad_update(aad).context("aad_update failed")?;

    let mut out = vec![0u8; plaintext.len() + cipher.block_size()];
    let mut count = crypter
        .update(plaintext, &mut out)
        .context("encrypt update failed")?;
    count += crypter
        .finalize(&mut out[count..])
        .context("encrypt finalize failed")?;
    out.truncate(count);

    let mut tag = [0u8; 16];
    crypter.get_tag(&mut tag).context("get_tag failed")?;
    out.extend_from_slice(&tag);
    Ok(out)
}

fn build_nonce(counter: u64, stream_type: u8) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0] = stream_type;
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>> {
    if s.len() != 64 {
        bail!("Key must be 64 hex chars (32 bytes)");
    }cargo
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.into()))
        .collect()
}

fn main() -> Result<()> {
    let key_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let key = hex_to_bytes(key_hex)?;

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();

    let mut counter: u64 = 0;

    loop {
        let mut stream_buf = [0u8; 1];
        if let Err(_) = input.read_exact(&mut stream_buf) {
            break;
        }
        let stream_type = stream_buf[0];

        let mut len_buf = [0u8; 4];
        input.read_exact(&mut len_buf)?;
        let payload_len = u32::from_be_bytes(len_buf) as usize;

        let mut aad_len_buf = [0u8; 4];
        input.read_exact(&mut aad_len_buf)?;
        let aad_len = u32::from_be_bytes(aad_len_buf) as usize;

        let mut aad = vec![0u8; aad_len];
        input.read_exact(&mut aad)?;

        let mut payload = vec![0u8; payload_len];
        input.read_exact(&mut payload)?;

        let nonce = build_nonce(counter, stream_type);
        counter = counter.wrapping_add(1);

        let ciphertext = aes_gcm_encrypt(&key, &nonce, &aad, &payload)?;

        output.write_all(&nonce)?;
        output.write_all(&(ciphertext.len() as u32).to_be_bytes())?;
        output.write_all(&ciphertext)?;
        output.flush()?;
    }

    Ok(())
}