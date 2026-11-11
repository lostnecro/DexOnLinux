#!/usr/bin/env python3
"""dex-on-linux: Run real Samsung DeX over USB on Linux.

Implements Samsung's DeX on PC (DOP) USB + ECDH-P521 + AES-256-CBC + WimpManager
+ Wi-Fi Display (RTSP M1-M7) protocol over ADB/USB to trigger genuine Samsung DeX
(com.sec.android.app.desktoplauncher & com.sec.android.dexsystemui) on displayId 2,
and attaches scrcpy to the Samsung DeX display.
"""

import argparse
import base64
import ctypes
import ctypes.util
import fcntl
import glob
import hashlib
import hmac
import json
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

# ============================================================================
# OpenSSL (libcrypto) bindings for NIST P-521 ECDH & AES-256-CBC
# ============================================================================
NID_secp521r1 = 716
POINT_CONVERSION_UNCOMPRESSED = 4
SIDESYNC_IV = hashlib.md5(b"com.sec.android.sidesync").digest()  # 16 bytes


def _load_libcrypto():
    path = ctypes.util.find_library("crypto")
    if not path:
        for d in os.environ.get("LD_LIBRARY_PATH", "").split(":"):
            if not d:
                continue
            for name in ("libcrypto.so", "libcrypto.so.3"):
                cand = os.path.join(d, name)
                if os.path.exists(cand):
                    path = cand
                    break
            if path:
                break
    if not path:
        matches = sorted(glob.glob("/nix/store/*-openssl-*/lib/libcrypto.so*"))
        if matches:
            path = matches[-1]
    if not path:
        path = "libcrypto.so.3"
    lib = ctypes.CDLL(path)

    lib.EC_KEY_new_by_curve_name.argtypes = [ctypes.c_int]
    lib.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
    lib.EC_KEY_free.argtypes = [ctypes.c_void_p]
    lib.EC_KEY_generate_key.argtypes = [ctypes.c_void_p]
    lib.EC_KEY_generate_key.restype = ctypes.c_int
    lib.EC_KEY_get0_group.argtypes = [ctypes.c_void_p]
    lib.EC_KEY_get0_group.restype = ctypes.c_void_p
    lib.EC_KEY_get0_public_key.argtypes = [ctypes.c_void_p]
    lib.EC_KEY_get0_public_key.restype = ctypes.c_void_p

    lib.EC_POINT_new.argtypes = [ctypes.c_void_p]
    lib.EC_POINT_new.restype = ctypes.c_void_p
    lib.EC_POINT_free.argtypes = [ctypes.c_void_p]
    lib.EC_POINT_oct2point.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
    ]
    lib.EC_POINT_oct2point.restype = ctypes.c_int
    lib.EC_POINT_point2oct.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
    ]
    lib.EC_POINT_point2oct.restype = ctypes.c_size_t

    lib.ECDH_compute_key.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    lib.ECDH_compute_key.restype = ctypes.c_int

    lib.EVP_CIPHER_CTX_new.argtypes = []
    lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    lib.EVP_aes_256_cbc.argtypes = []
    lib.EVP_aes_256_cbc.restype = ctypes.c_void_p
    lib.EVP_CipherInit_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    lib.EVP_CipherInit_ex.restype = ctypes.c_int
    lib.EVP_CipherUpdate.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    lib.EVP_CipherUpdate.restype = ctypes.c_int
    lib.EVP_CipherFinal_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_int),
    ]
    lib.EVP_CipherFinal_ex.restype = ctypes.c_int
    return lib


_libcrypto = _load_libcrypto()


def aes256_cbc(key: bytes, data: bytes, encrypt: bool) -> bytes:
    ctx = _libcrypto.EVP_CIPHER_CTX_new()
    try:
        if (
            _libcrypto.EVP_CipherInit_ex(
                ctx,
                _libcrypto.EVP_aes_256_cbc(),
                None,
                key,
                SIDESYNC_IV,
                1 if encrypt else 0,
            )
            != 1
        ):
            raise RuntimeError("EVP_CipherInit_ex failed")
        out_buf = ctypes.create_string_buffer(len(data) + 32)
        out_len1 = ctypes.c_int(0)
        if (
            _libcrypto.EVP_CipherUpdate(
                ctx, out_buf, ctypes.byref(out_len1), data, len(data)
            )
            != 1
        ):
            raise RuntimeError("EVP_CipherUpdate failed")
        out_len2 = ctypes.c_int(0)
        ptr2 = ctypes.cast(
            ctypes.addressof(out_buf) + out_len1.value, ctypes.c_char_p
        )
        if _libcrypto.EVP_CipherFinal_ex(ctx, ptr2, ctypes.byref(out_len2)) != 1:
            raise RuntimeError("EVP_CipherFinal_ex failed")
        return out_buf.raw[: out_len1.value + out_len2.value]
    finally:
        _libcrypto.EVP_CIPHER_CTX_free(ctx)


def aes_encrypt_str(key: bytes, plaintext: str) -> bytes:
    return aes256_cbc(key, plaintext.encode("utf-8"), True)


def aes_decrypt_str(key: bytes, ciphertext: bytes) -> str:
    return aes256_cbc(key, ciphertext, False).decode("utf-8")


# ============================================================================
# USB conn_gadget (Interface 3: 0xFF/0xF0/0x00, EP_OUT=0x03, EP_IN=0x85)
# ============================================================================
USBDEVFS_BULK = 0xC0185502
USBDEVFS_CLAIMINTERFACE = 0x8004550F
USBDEVFS_RELEASEINTERFACE = 0x80045510
USBDEVFS_RESET = 0x5514


class UsbBulkTransfer(ctypes.Structure):
    _fields_ = [
        ("ep", ctypes.c_uint),
        ("len", ctypes.c_uint),
        ("timeout", ctypes.c_uint),
        ("data", ctypes.c_void_p),
    ]


def find_samsung_usb_dev() -> str:
    for dev in sorted(glob.glob("/sys/bus/usb/devices/*")):
        vid_p = os.path.join(dev, "idVendor")
        if not os.path.exists(vid_p):
            continue
        try:
            with open(vid_p) as f:
                vid = f.read().strip()
            if vid != "04e8":
                continue
            with open(os.path.join(dev, "busnum")) as f:
                bus = int(f.read().strip())
            with open(os.path.join(dev, "devnum")) as f:
                devnum = int(f.read().strip())
            return f"/dev/bus/usb/{bus:03d}/{devnum:03d}"
        except OSError:
            continue
    raise RuntimeError("Samsung USB device (VID 04e8) not found on /sys/bus/usb/devices")


def try_send_conn_pkt(dev_path: str) -> bool:
    fd = os.open(dev_path, os.O_RDWR)
    try:
        iface = ctypes.c_uint(3)
        fcntl.ioctl(fd, USBDEVFS_CLAIMINTERFACE, iface)
        try:
            msg = b"dop pc app start|2026-11-11 13:45:00.000"
            body = msg.ljust(256, b" ")
            pkt = struct.pack("<IIII", 1313754947, 12, 272, 3) + body
            buf = ctypes.create_string_buffer(pkt, len(pkt))
            bulk = UsbBulkTransfer(
                ep=0x03, len=len(pkt), timeout=2000, data=ctypes.addressof(buf)
            )
            fcntl.ioctl(fd, USBDEVFS_BULK, bulk)

            in_buf = ctypes.create_string_buffer(512)
            bulk_in = UsbBulkTransfer(
                ep=0x85, len=512, timeout=3000, data=ctypes.addressof(in_buf)
            )
            rcvd = fcntl.ioctl(fd, USBDEVFS_BULK, bulk_in)
            raw = in_buf.raw[:rcvd]
            return b"dex live device app start" in raw
        except OSError:
            return False
        finally:
            fcntl.ioctl(fd, USBDEVFS_RELEASEINTERFACE, iface)
    finally:
        os.close(fd)


def ensure_dop_main_server(serial: str):
    """Ensure DOPService MainServer is listening on 127.0.0.1:15000 on the phone."""
    chk = subprocess.run(
        ["adb", "-s", serial, "shell", "ss -tln | grep -q ':15000 '"],
        capture_output=True,
    )
    if chk.returncode == 0:
        return

    dev_path = find_samsung_usb_dev()
    print(f"[DeX] Waking Samsung DeX service on {dev_path}...", file=sys.stderr)
    if try_send_conn_pkt(dev_path):
        return

    subprocess.run(["adb", "kill-server"], check=False)
    fd = os.open(dev_path, os.O_RDWR)
    try:
        fcntl.ioctl(fd, USBDEVFS_RESET, 0)
    finally:
        os.close(fd)
    time.sleep(2.0)
    dev_path = find_samsung_usb_dev()
    if not try_send_conn_pkt(dev_path):
        subprocess.run(["adb", "start-server"], check=False)
        raise RuntimeError(
            "Failed to receive 'dex live device app start' from USB conn_gadget"
        )
    subprocess.run(["adb", "start-server"], check=True)
    subprocess.run(["adb", "-s", serial, "wait-for-device"], check=True)


# ============================================================================
# Samsung DeX on PC Protocol (MainServer + WimpManager + WFD RTSP M1-M7)
# ============================================================================
CLIENT_MAC = "00:00:00:00:00:00"
LOCAL_IDC_PORT = 7247

# Map resolution strings to WFD (CEA mask, VESA mask) hex strings
WFD_RESOLUTIONS = {
    "1920x1080": ("00000080", "00000000"),  # CEA index 7: 1920x1080p30
    "1280x720": ("00000020", "00000000"),   # CEA index 5: 1280x720p30
    "1600x900": ("00000000", "00004000"),   # VESA index 14: 1600x900p30
    "2560x1440": ("00000000", "40000000"),  # VESA index 30: 2560x1440p30
}


def write_utf(sock: socket.socket, s: str):
    data = s.encode("utf-8")
    sock.sendall(struct.pack(">H", len(data)) + data)


def read_utf(sock: socket.socket) -> str:
    hdr = b""
    while len(hdr) < 2:
        chunk = sock.recv(2 - len(hdr))
        if not chunk:
            raise EOFError("Socket closed reading UTF length")
        hdr += chunk
    (length,) = struct.unpack(">H", hdr)
    body = b""
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            raise EOFError("Socket closed reading UTF body")
        body += chunk
    return body.decode("utf-8")


def send_idc_cmd(
    port: int, session_key: bytes, cmd_str: str, expect_resp: bool = False
):
    s = socket.create_connection(("127.0.0.1", port), timeout=10.0)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        enc_b64 = base64.b64encode(aes_encrypt_str(session_key, cmd_str)).decode(
            "ascii"
        )
        write_utf(s, enc_b64)
        if expect_resp:
            resp_b64 = read_utf(s)
            return aes_decrypt_str(session_key, base64.b64decode(resp_b64))
        time.sleep(0.1)
        return None
    finally:
        s.close()


class DexSession:
    """Manages the Samsung DeX on PC control channels and RTSP keepalive."""

    def __init__(self, serial: str, size: str, auto_accept: bool = True):
        self.serial = serial
        self.size = size
        self.auto_accept = auto_accept
        self.stop_event = threading.Event()
        self.main_sock = None
        self.idc_srv = None
        self.rtsp_sock = None

    def _adb(self, *args, check=True):
        return subprocess.run(
            ["adb", "-s", self.serial, *args],
            capture_output=True,
            text=True,
            check=check,
        )

    def start(self) -> int:
        ensure_dop_main_server(self.serial)
        self._adb("wait-for-device")
        self._adb("forward", "tcp:15000", "tcp:15000")
        self._adb("forward", "tcp:7246", "tcp:7246")
        self._adb("forward", "tcp:7236", "tcp:7236")
        self._adb("reverse", f"tcp:{LOCAL_IDC_PORT}", f"tcp:{LOCAL_IDC_PORT}")

        session_key_holder = [None]
        src_work_event = threading.Event()
        wfd_ready_event = threading.Event()

        # 1. Start local IDC listener on port 7247
        self.idc_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.idc_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.idc_srv.bind(("127.0.0.1", LOCAL_IDC_PORT))
        self.idc_srv.listen(16)

        def idc_server_loop():
            while not self.stop_event.is_set():
                try:
                    conn, _ = self.idc_srv.accept()
                except OSError:
                    break
                try:
                    utf = read_utf(conn)
                    if session_key_holder[0] is not None and len(utf.split(" ")) <= 5:
                        dec = aes_decrypt_str(
                            session_key_holder[0], base64.b64decode(utf)
                        )
                    else:
                        dec = utf
                    if "SRC_STATE_CHANGE EVENT 5" in dec:
                        src_work_event.set()
                    elif "SCR_SHR_ENABLED EVENT 1/&%1" in dec:
                        wfd_ready_event.set()
                except Exception:
                    pass
                finally:
                    conn.close()

        threading.Thread(target=idc_server_loop, daemon=True).start()

        # 2. Connect to MainServer on 127.0.0.1:15000 and authenticate (ECDH P-521)
        print("[DeX] Authenticating with DOP MainServer...", file=sys.stderr)
        self.main_sock = socket.create_connection(("127.0.0.1", 15000), timeout=15.0)
        self.main_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        main_lock = threading.Lock()

        def send_main_frame(_is_enc: bool, payload: bytes, session_id: int):
            hdr = struct.pack(">II", len(payload), session_id)
            with main_lock:
                self.main_sock.sendall(hdr + payload)

        def recv_main_frame():
            hdr = b""
            while len(hdr) < 8:
                chunk = self.main_sock.recv(8 - len(hdr))
                if not chunk:
                    raise EOFError("MainServer closed connection")
                hdr += chunk
            length, sid = struct.unpack(">II", hdr)
            body = b""
            while len(body) < length:
                chunk = self.main_sock.recv(length - len(body))
                if not chunk:
                    raise EOFError("MainServer closed mid-frame")
                body += chunk
            try:
                text = body.decode("utf-8")
                if not (text.startswith("{") and "TYPE" in text):
                    raise UnicodeDecodeError("utf-8", body, 0, 1, "encrypted")
            except UnicodeDecodeError:
                text = aes_decrypt_str(session_key_holder[0], body)
            return sid, json.loads(text)

        # AUTH SEQ1
        seq1_req = json.dumps(
            {"TYPE": "AUTH", "MSG": "SEQ1", "PARAM": {"MAC": CLIENT_MAC}},
            separators=(",", ":"),
        ).encode("utf-8")
        send_main_frame(False, seq1_req, 1)
        _, seq1_resp = recv_main_frame()
        phone_uid_b64 = seq1_resp["PARAM"]["UID"]

        # AUTH SEQ2 (Generate NIST P-521 keypair)
        ec_key = _libcrypto.EC_KEY_new_by_curve_name(NID_secp521r1)
        if _libcrypto.EC_KEY_generate_key(ec_key) != 1:
            raise RuntimeError("EC_KEY_generate_key failed")
        group = _libcrypto.EC_KEY_get0_group(ec_key)
        pub_pt = _libcrypto.EC_KEY_get0_public_key(ec_key)
        pub_buf = ctypes.create_string_buffer(133)
        pub_len = _libcrypto.EC_POINT_point2oct(
            group, pub_pt, POINT_CONVERSION_UNCOMPRESSED, pub_buf, 133, None
        )
        my_pub_b64 = base64.b64encode(pub_buf.raw[:pub_len]).decode("ascii")

        seq2_req = json.dumps(
            {"TYPE": "AUTH", "MSG": "SEQ2", "PARAM": {"PubKey": my_pub_b64}},
            separators=(",", ":"),
        ).encode("utf-8")
        send_main_frame(False, seq2_req, 2)
        _, seq2_resp = recv_main_frame()

        phone_pub_b64 = seq2_resp["PARAM"]["PubKey"]
        peer_pub_bytes = base64.b64decode(phone_pub_b64)
        peer_pt = _libcrypto.EC_POINT_new(group)
        if (
            _libcrypto.EC_POINT_oct2point(
                group, peer_pt, peer_pub_bytes, len(peer_pub_bytes), None
            )
            != 1
        ):
            raise RuntimeError("EC_POINT_oct2point failed")
        shared_buf = ctypes.create_string_buffer(66)
        shared_len = _libcrypto.ECDH_compute_key(
            shared_buf, 66, peer_pt, ec_key, None
        )
        shared_secret = shared_buf.raw[:shared_len]

        msg_to_mac = phone_pub_b64 + my_pub_b64 + phone_uid_b64 + CLIENT_MAC
        my_hmac_b64 = base64.b64encode(
            hmac.new(
                shared_secret, msg_to_mac.encode("utf-8"), hashlib.sha256
            ).digest()
        ).decode("ascii")

        sk_input = (
            shared_secret.hex().upper() + CLIENT_MAC + phone_uid_b64
        ).encode("utf-8")
        session_key = hashlib.sha256(sk_input).digest()
        session_key_holder[0] = session_key

        # AUTH SEQ3
        seq3_req = json.dumps(
            {"TYPE": "AUTH", "MSG": "SEQ3", "PARAM": {"HMAC": my_hmac_b64}},
            separators=(",", ":"),
        ).encode("utf-8")
        send_main_frame(False, seq3_req, 3)
        _, seq3_resp = recv_main_frame()
        if not seq3_resp["PARAM"].get("Verified"):
            raise RuntimeError("DOP MainServer AUTH SEQ3 verification failed")

        # 3. Send TerminalInfo and ChangePSSState
        term_info_req = json.dumps(
            {
                "TYPE": "REQ",
                "MSG": "TerminalInfo",
                "PARAM": {
                    "SinkMAC": CLIENT_MAC,
                    "SinkName": "Linux PC",
                    "SinkIP": "127.0.0.1",
                    "KmsVer": "2.0",
                    "SinkType": "Windows",
                    "PcVer": "2.4.1.18",
                    "SinkApkVersion": "2.5.00.16",
                    "ConnectedSourceIP": "127.0.0.1",
                    "SinkIDCConnectBeforehand": True,
                    "SinkAutoStartStatus": True,
                    "SinkNotificationStatus": False,
                    "SinkCmdAsCtrlStatus": False,
                    "SinkOSVersion": "10.0",
                    "SinkUIRatio": "100.0",
                    "SinkSilentInstallCount": 1,
                    "WifiConnectivity": "0",
                },
            },
            separators=(",", ":"),
        )
        send_main_frame(True, aes_encrypt_str(session_key, term_info_req), 4)
        recv_main_frame()

        pss_req = json.dumps(
            {
                "TYPE": "REQ",
                "MSG": "ChangePSSState",
                "PARAM": {"PSS_STATE": 1, "PSS_MODE": 0},
            },
            separators=(",", ":"),
        )
        send_main_frame(True, aes_encrypt_str(session_key, pss_req), 5)

        pss_ready_event = threading.Event()

        def main_keepalive_and_reader():
            def ka_sender():
                sid_counter = 100
                while not self.stop_event.is_set():
                    time.sleep(5.0)
                    if self.stop_event.is_set():
                        break
                    try:
                        ka = json.dumps(
                            {"TYPE": "REQ", "MSG": "CheckConnect"},
                            separators=(",", ":"),
                        ).encode("utf-8")
                        send_main_frame(False, ka, sid_counter)
                        sid_counter += 1
                    except Exception:
                        break

            threading.Thread(target=ka_sender, daemon=True).start()
            while not self.stop_event.is_set():
                try:
                    _, msg = recv_main_frame()
                    if msg.get("MSG") == "ChangePSSState":
                        pss_ready_event.set()
                except Exception:
                    break

        threading.Thread(target=main_keepalive_and_reader, daemon=True).start()

        if not pss_ready_event.wait(timeout=15.0):
            raise RuntimeError("Timed out waiting for ChangePSSState from phone")

        # 4. Connect to WimpManager on 127.0.0.1:7246 (SIDESYNC_CONN)
        sidesync_info = f"{LOCAL_IDC_PORT}/&%{CLIENT_MAC}/&%123456/&%false/&%127.0.0.1/&%PC/&%USB/&%Linux PC"
        sidesync_cmd = (
            f"{len(sidesync_info)} 1 CONNECT SIDESYNC_CONN REQUEST {sidesync_info}"
        )
        resp_str = None
        for _ in range(15):
            try:
                resp_str = send_idc_cmd(
                    7246, session_key, sidesync_cmd, expect_resp=True
                )
                break
            except Exception:
                time.sleep(0.3)
        if not resp_str:
            raise RuntimeError("Failed to connect to WimpManager on port 7246")

        resp_info = resp_str.split(" ", 5)[5]
        phone_control_port = int(resp_info.split("/&%")[0])
        self._adb(
            "forward", f"tcp:{phone_control_port}", f"tcp:{phone_control_port}"
        )

        if not src_work_event.wait(timeout=15.0):
            raise RuntimeError("Timed out waiting for SRC_STATE_CHANGE EVENT 5")

        # 5. Send ENABLE_SCR_SHR to phone's CONTROL port
        print(
            "[DeX] Requesting Samsung DeX screen share (ENABLE_SCR_SHR)...",
            file=sys.stderr,
        )
        send_idc_cmd(
            phone_control_port,
            session_key,
            "4 2 SCR_SHR ENABLE_SCR_SHR EVENT null",
            expect_resp=False,
        )

        # Auto-confirm "Start Samsung DeX?" dialog on phone if enabled
        if self.auto_accept:

            def auto_accept_popup():
                for _ in range(15):
                    if wfd_ready_event.is_set() or self.stop_event.is_set():
                        return
                    time.sleep(0.4)
                    res = self._adb(
                        "shell",
                        "uiautomator dump /sdcard/.dex_ui.xml >/dev/null 2>&1 && cat /sdcard/.dex_ui.xml; rm -f /sdcard/.dex_ui.xml",
                        check=False,
                    )
                    if "com.sec.android.app.dexonpc" not in res.stdout:
                        continue
                    m = re.search(
                        r'resource-id="android:id/button1"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
                        res.stdout,
                    )
                    if m:
                        x = (int(m.group(1)) + int(m.group(3))) // 2
                        y = (int(m.group(2)) + int(m.group(4))) // 2
                        print(
                            "[DeX] Auto-accepting 'Start Samsung DeX' prompt on phone...",
                            file=sys.stderr,
                        )
                        self._adb("shell", f"input tap {x} {y}", check=False)
                        return

            threading.Thread(target=auto_accept_popup, daemon=True).start()

        # 6. Poll 127.0.0.1:7236 for Phone WFD RTSP Server (M1 OPTIONS)
        buf = b""
        deadline = time.time() + 25.0
        while time.time() < deadline and not self.stop_event.is_set():
            try:
                s = socket.create_connection(("127.0.0.1", 7236), timeout=1.0)
                s.settimeout(0.8)
                chunk = s.recv(4096)
                if chunk:
                    wfd_ready_event.set()
                    self.rtsp_sock = s
                    self.rtsp_sock.settimeout(35.0)
                    buf = chunk
                    break
                s.close()
            except Exception:
                pass
            time.sleep(0.3)

        if self.rtsp_sock is None:
            raise RuntimeError(
                "Timed out waiting for Samsung DeX WFD RTSP server on port 7236"
            )

        # 7. Complete RTSP M1-M7 negotiation and keep session alive in background
        dex_started_event = threading.Event()
        cea_mask, vesa_mask = WFD_RESOLUTIONS.get(
            self.size, WFD_RESOLUTIONS["1920x1080"]
        )

        def rtsp_loop():
            nonlocal buf
            session_id = "12345678"
            cseq_client = 100
            while not self.stop_event.is_set():
                try:
                    if not buf:
                        chunk = self.rtsp_sock.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
                    while b"\r\n\r\n" in buf:
                        hdr_part, rest = buf.split(b"\r\n\r\n", 1)
                        hdr_text = hdr_part.decode("utf-8", errors="replace")
                        cl_match = re.search(
                            r"Content-Length:\s*(\d+)", hdr_text, re.IGNORECASE
                        )
                        body_len = int(cl_match.group(1)) if cl_match else 0
                        if len(rest) < body_len:
                            chunk = self.rtsp_sock.recv(4096)
                            if not chunk:
                                return
                            buf += chunk
                            continue
                        body_text = rest[:body_len].decode(
                            "utf-8", errors="replace"
                        )
                        buf = rest[body_len:]

                        first_line = hdr_text.splitlines()[0]
                        cseq_m = re.search(
                            r"CSeq:\s*(\d+)", hdr_text, re.IGNORECASE
                        )
                        cseq = int(cseq_m.group(1)) if cseq_m else 1

                        if first_line.startswith("OPTIONS"):
                            m1_resp = (
                                f"RTSP/1.0 200 OK\r\n"
                                f"CSeq: {cseq}\r\n"
                                f"Public: org.wfa.wfd1.0, GET_PARAMETER, SET_PARAMETER\r\n\r\n"
                            )
                            self.rtsp_sock.sendall(m1_resp.encode("utf-8"))

                            m2_req = (
                                f"OPTIONS * RTSP/1.0\r\n"
                                f"CSeq: {cseq_client}\r\n"
                                f"Require: org.wfa.wfd1.0\r\n"
                                f"User-Agent: SEC-WFD-SINK/1.0\r\n\r\n"
                            )
                            cseq_client += 1
                            self.rtsp_sock.sendall(m2_req.encode("utf-8"))

                        elif first_line.startswith("GET_PARAMETER"):
                            if "wfd_video_formats" in body_text:
                                m3_lines = []
                                for req_line in body_text.splitlines():
                                    param = req_line.strip()
                                    if not param:
                                        continue
                                    if param == "wfd_video_formats":
                                        m3_lines.append(
                                            f"wfd_video_formats: 00 00 02 04 {cea_mask} {vesa_mask} 00000000 00 0000 0000 00 none none"
                                        )
                                    elif param == "wfd_audio_codecs":
                                        m3_lines.append(
                                            "wfd_audio_codecs: LPCM 00000003 00, AAC 00000001 00"
                                        )
                                    elif param == "wfd_client_rtp_ports":
                                        # Port 19000 loops back to RTPSender's own socket on 127.0.0.1
                                        m3_lines.append(
                                            "wfd_client_rtp_ports: RTP/AVP/UDP;unicast 19000 0 mode=play"
                                        )
                                    else:
                                        m3_lines.append(f"{param}: none")
                                m3_body = "\r\n".join(m3_lines) + "\r\n"
                                m3_resp = (
                                    f"RTSP/1.0 200 OK\r\n"
                                    f"CSeq: {cseq}\r\n"
                                    f"Content-Type: text/parameters\r\n"
                                    f"Content-Length: {len(m3_body)}\r\n\r\n"
                                    f"{m3_body}"
                                )
                                self.rtsp_sock.sendall(m3_resp.encode("utf-8"))
                            else:
                                ka_resp = f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n\r\n"
                                self.rtsp_sock.sendall(ka_resp.encode("utf-8"))

                        elif first_line.startswith("SET_PARAMETER"):
                            resp = f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n\r\n"
                            self.rtsp_sock.sendall(resp.encode("utf-8"))

                            if "wfd_trigger_method: SETUP" in body_text:
                                m6_req = (
                                    f"SETUP rtsp://127.0.0.1/wfd1.0/streamid=0 RTSP/1.0\r\n"
                                    f"CSeq: {cseq_client}\r\n"
                                    f"Transport: RTP/AVP/UDP;unicast;client_port=19000\r\n\r\n"
                                )
                                cseq_client += 1
                                self.rtsp_sock.sendall(m6_req.encode("utf-8"))

                        elif first_line.startswith("RTSP/1.0 200 OK"):
                            sess_m = re.search(
                                r"Session:\s*([^\r\n;]+)", hdr_text, re.IGNORECASE
                            )
                            if sess_m and "Transport:" in hdr_text:
                                session_id = sess_m.group(1).strip()
                                m7_req = (
                                    f"PLAY rtsp://127.0.0.1/wfd1.0/streamid=0 RTSP/1.0\r\n"
                                    f"CSeq: {cseq_client}\r\n"
                                    f"Session: {session_id}\r\n\r\n"
                                )
                                cseq_client += 1
                                self.rtsp_sock.sendall(m7_req.encode("utf-8"))
                            elif sess_m:
                                dex_started_event.set()
                except Exception:
                    break

        threading.Thread(target=rtsp_loop, daemon=True).start()

        if not dex_started_event.wait(timeout=15.0):
            raise RuntimeError("Timed out completing WFD RTSP M1-M7 handshake")

        # Wait briefly for DualModeChanger to finish enabling desktopDisplay.2
        print("[DeX] Waiting for Samsung DeX desktop display...", file=sys.stderr)
        for _ in range(20):
            out = self._adb(
                "shell",
                "dumpsys window displays | grep 'mDisplayId=2'",
                check=False,
            ).stdout
            if "mDisplayId=2" in out:
                break
            time.sleep(0.25)

        return 2

    def close(self):
        self.stop_event.set()
        for sock in (self.rtsp_sock, self.main_sock, self.idc_srv):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self._adb("forward", "--remove-all", check=False)
        self._adb("reverse", "--remove-all", check=False)


def die(message: str):
    sys.exit(f"dex-on-linux: {message}")


def pick_device(serial: str | None) -> str:
    if serial:
        return serial
    listing = subprocess.run(["adb", "devices"], capture_output=True, text=True)
    lines = [line.split("\t") for line in listing.stdout.splitlines()[1:] if line]
    ready = [fields[0] for fields in lines if fields[-1] == "device"]
    if len(ready) == 1:
        return ready[0]
    if not ready:
        waiting = ", ".join(f"{f[0]} ({f[-1]})" for f in lines) or "none"
        die(
            "no authorized Android device found (seen: "
            f"{waiting}). Enable USB debugging and accept the prompt on the phone."
        )
    die(f"several devices connected, choose one with --serial: {', '.join(ready)}")


def main():
    parser = argparse.ArgumentParser(
        prog="dex-on-linux",
        description="Run real Samsung DeX over USB in a window on Linux.",
        epilog="Arguments after -- are passed to scrcpy, e.g. "
        "`dex-on-linux -- --fullscreen --keyboard=uhid`.",
    )
    parser.add_argument("-s", "--serial", help="ADB serial of the Samsung phone")
    parser.add_argument(
        "--size",
        default="1920x1080",
        choices=list(WFD_RESOLUTIONS.keys()),
        help="Samsung DeX resolution (default: %(default)s)",
    )
    parser.add_argument(
        "--no-auto-accept",
        action="store_true",
        help="do not automatically tap the 'Start Samsung DeX' prompt on the phone",
    )
    args, scrcpy_args = parser.parse_known_args()
    if scrcpy_args and scrcpy_args[0] == "--":
        scrcpy_args = scrcpy_args[1:]

    for tool in ("adb", "scrcpy"):
        if not shutil.which(tool):
            die(f"`{tool}` was not found in PATH")

    serial = pick_device(args.serial)
    session = DexSession(
        serial=serial, size=args.size, auto_accept=not args.no_auto_accept
    )

    try:
        display_id = session.start()
        print(
            f"[DeX] Samsung DeX is active on display {display_id}! Launching scrcpy...",
            file=sys.stderr,
        )
        scrcpy_cmd = [
            "scrcpy",
            "-s",
            serial,
            f"--display-id={display_id}",
            "--window-title=Samsung DeX",
            "--mouse-bind=++++:bhsn",
            "--stay-awake",
            *scrcpy_args,
        ]
        proc = subprocess.Popen(scrcpy_cmd)
        signal.signal(signal.SIGTERM, lambda *_: proc.terminate())
        try:
            rc = proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            rc = proc.wait()
        sys.exit(rc)
    finally:
        print("[DeX] Closing Samsung DeX session...", file=sys.stderr)
        session.close()


if __name__ == "__main__":
    main()
