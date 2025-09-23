use openssl::symm::{Cipher, Crypter, Mode};
use rand::RngCore;
use std::io::{self, Read, Write};
use base64::{engine::general_purpose, Engine};

fn main() {
    let stdin = io::stdin();
    let mut stdin_lock = stdin.lock();
    let mut buffer = [0u8; 4];

    loop {
        // Read length prefix (4 bytes)
        if stdin_lock.read_exact(&mut buffer).is_err() {
            break; // end of stream
        }
        let frame_size = u32::from_be_bytes(buffer) as usize;

        let mut frame_data = vec![0u8; frame_size];
        if stdin_lock.read_exact(&mut frame_data).is_err() {
            break;
        }

        // Generate key & IV
        let mut key = [0u8; 32];
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut key);
        rand::thread_rng().fill_bytes(&mut iv);

        //Encrypt
        let cipher = Cipher::aes_256_cbc();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv)).unwrap();
        crypter.pad(true);
        
        let mut ciphertext = vec![0; frame_data.len() + cipher.block_size()];
        let mut count = crypter.update(&frame_data, &mut ciphertext).unwrap();
        count += crypter.finalize(&mut ciphertext[count..]).unwrap();
        ciphertext.truncate(count);
        
        crypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv)).unwrap();
        crypter.pad(true);
        
        ciphertext = vec![0; frame_data.len() + cipher.block_size()];
        count = crypter.update(&frame_data, &mut ciphertext).unwrap();
        count += crypter.finalize(&mut ciphertext[count..]).unwrap();
        ciphertext.truncate(count);
        
        // Send result as base64-encoded JSON line
        let key_b64 = general_purpose::STANDARD.encode(&key);
        let iv_b64 = general_purpose::STANDARD.encode(&iv);
        let data_b64 = general_purpose::STANDARD.encode(&ciphertext);

        let output = format!(
            "{{\"key\":\"{}\",\"iv\":\"{}\",\"data\":\"{}\"}}\n",
            key_b64, iv_b64, data_b64
        );

        io::stdout().write_all(output.as_bytes()).unwrap();
        io::stdout().flush().unwrap();
    }
}
