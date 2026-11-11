# DexOnLinux

Run genuine **Samsung DeX (`DEX_ON_PC`)** over USB on Linux.

Unlike solutions that spawn a generic Android desktop on a virtual display, this project reverse-engineers Samsung's official **DeX on PC (DOP)** protocol to trigger the real Samsung DeX environment (`com.sec.android.app.desktoplauncher` and `com.sec.android.dexsystemui`) and displays it seamlessly on Linux using `scrcpy`.

> [!NOTE]
> **Disclaimer:** This project was developed **entirely with AI** and was created for **personal use**. It is provided as-is, without warranties, and you should not expect frequent updates or active maintenance.

---

## How It Works

Samsung's DeX on PC protocol relies on several proprietary handshake stages over USB and ADB:

1. **USB `conn_gadget` Wakeup:** Triggers Samsung's `DOPService` by sending an initiation control packet over USB interface 3 (`EP 0x03` / `EP 0x85`) if the service isn't already active.
2. **ECDH P-521 Key Exchange & Authentication:** Connects to Samsung's `MainServer` on port `15000` via ADB port forwarding, performs a NIST P-521 elliptic-curve Diffie-Hellman handshake, verifies HMAC-SHA256, and establishes AES-256-CBC session encryption.
3. **WimpManager & Screen Share Request:** Communicates with `WimpManager` on port `7246` and phone control ports to request `ENABLE_SCR_SHR`.
4. **Wi-Fi Display (WFD) RTSP Negotiation:** Handles the RTSP `M1`–`M7` handshake (`OPTIONS`, `GET_PARAMETER`, `SET_PARAMETER`, `SETUP`, `PLAY`) on port `7236`, which prompts Samsung's `DualModeChanger` to spin up the DeX desktop on display ID 2.
5. **Display & Input:** Attaches `scrcpy` directly to the active Samsung DeX display (`--display-id=2`) with proper mouse and keyboard bindings.

---

## Prerequisites

- **Samsung Galaxy Device** with Samsung DeX support (e.g. S-series, Note-series, Z Fold).
- **USB Cable** connected to your Linux machine.
- **USB Debugging (ADB)** enabled on your phone.
- **Dependencies:**
  - `adb` (Android platform tools)
  - `scrcpy`
  - `python3` with OpenSSL (`libcrypto`)

---

## Quick Start (Nix / NixOS)

If you use Nix with flakes enabled, you can run it directly:

```bash
nix run github:lostnecro/DexOnLinux
```

Or from a local clone:

```bash
nix run .
```

### Options

Pass options to configure resolution or forward flags to `scrcpy`:

```bash
# Set DeX desktop resolution (options: 1920x1080, 2560x1440, 1600x900, 1280x720)
nix run . -- --size 2560x1440

# Pass arguments directly to scrcpy (e.g. fullscreen)
nix run . -- --fullscreen

# Disable automatically tapping "Start now" prompt on phone
nix run . -- --no-auto-accept
```

---

## Running on Non-Nix Linux

Make sure `adb`, `scrcpy`, `python3`, and OpenSSL are installed via your system package manager.

```bash
# Clone the repository
git clone https://github.com/lostnecro/DexOnLinux.git
cd DexOnLinux

# Run dex-on-linux
python3 dex_on_linux.py
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
