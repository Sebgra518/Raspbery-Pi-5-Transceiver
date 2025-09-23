# Raspberry Pi 5 Transceiver

Secure, bidirectional **video + audio streaming** over a LAN, built on a Raspberry Pi 5 with **Python control logic** and **Rust-based encryption** that leverages the Pi 5’s hardware crypto engine.  

> 💡 Imagine a DIY **encrypted doorbell camera**: video from a Pi Camera Module 2 and audio from a USB microphone, streamed live with end-to-end encryption.

---

## Features
- **Bidirectional live streaming** of video (Pi Camera Module 2) and audio (USB microphone)  
- **End-to-end encryption** implemented in Rust for security + performance  
- Uses the Raspberry Pi 5 **crypto engine** for efficient, low-latency encryption  
- **Python control logic** for stream orchestration  
- Configurable **bitrate and resolution** (roadmap: move to `.env` for user control)  
- LAN-based for private, secure use cases (doorbell cameras, local surveillance, secure comms)  

---

## Hardware
- Raspberry Pi 5 (16 GB)  
- Pi Camera Module 2  
- USB Microphone  
- Local Wi-Fi network  

---

## Software Stack
- **Python**: Orchestration, device control, streaming pipeline  
- **Rust**: Encryption logic (no garbage collection → lower latency, predictable performance)  
- **Dependencies**:  
  - Python: `opencv-python`, `pyaudio`, `requests`, `python-dotenv`  
  - Rust: `tokio`, `aes-gcm` (or whichever crypto crates you used), `serde`  

---

## Getting Started

### 1. Clone repo
```bash
git clone https://github.com/Sebgra518/Raspbery-Pi-5-Transceiver.git
cd Raspbery-Pi-5-Transceiver
