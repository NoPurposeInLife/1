#!/usr/bin/env python3
"""
Threaded HTTP/HTTPS MITM proxy with GUI intercept + hex edit.

Usage:
    python mitm_proxy_threaded.py --ca-cert burpsuite_ca_cert.der --ca-key burpsuite_ca_key.der --listen 127.0.0.1:8080

Dependencies:
    pip install PyQt5 cryptography

Notes:
- Supports DER or PEM for the CA cert/key; converts DER to PEM automatically.
- Uses per-host leaf certs signed by the provided CA.
- Thread-per-connection (blocking sockets) model to avoid asyncio private API issues.
- Plain HTTP and HTTPS (CONNECT) supported. HTTPS MITM requires client trusts CA.
"""

import socket
import threading
import argparse
import sys
import os
import tempfile
import time
import re
import traceback
from dataclasses import dataclass, field
from typing import Optional, Tuple
from queue import Queue, Empty
import wincertstore
import certifi

# GUI
from PyQt5 import QtWidgets, QtCore, QtGui

# crypto
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509 import NameOID, DNSName, SubjectAlternativeName, BasicConstraints
import datetime
import ipaddress

host = None
port_s = None

# -----------------------
# Utilities (hex/text)
# -----------------------
def bytes_to_hex_view(b: bytes) -> str:
    hexstr = b.hex()
    pairs = [hexstr[i:i+2] for i in range(0, len(hexstr), 2)]
    lines = []
    for i in range(0, len(pairs), 16):
        lines.append(" ".join(pairs[i:i+16]))
    return "\n".join(lines)

def hex_view_to_bytes(s: str) -> bytes:
    cleaned = re.sub(r'[^0-9a-fA-F]', '', s)
    if len(cleaned) % 2 == 1:
        cleaned = cleaned + "0"
    return bytes.fromhex(cleaned)

# -----------------------
# Transaction container
# -----------------------
@dataclass
class Transaction:
    id: int
    host: str
    port: int
    request_raw: bytes = b""
    response_raw: bytes = b""
    status: str = "pending"
    intercepted_request: bool = False
    intercepted_response: bool = False
    request_event: threading.Event = field(default_factory=threading.Event)
    response_event: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)

# -----------------------
# CA Provider (DER/PEM handling + leaf cert gen)
# -----------------------
class CAProvider:
    def __init__(self, ca_cert_path: str, ca_key_path: str):
        self.ca_cert_obj = None
        self.ca_key_obj = None
        self._cert_cache = {}  # host -> (cert_path, key_path, expiry_ts)
        self._load_ca(ca_cert_path, ca_key_path)

    def _try_load_cert(self, data: bytes):
        try:
            return x509.load_pem_x509_certificate(data)
        except Exception:
            return x509.load_der_x509_certificate(data)

    def _try_load_key(self, data: bytes):
        try:
            return serialization.load_pem_private_key(data, password=None)
        except Exception:
            return serialization.load_der_private_key(data, password=None)

    def _load_ca(self, cert_path, key_path):
        with open(cert_path, "rb") as f:
            certdata = f.read()
        with open(key_path, "rb") as f:
            keydata = f.read()
        self.ca_cert_obj = self._try_load_cert(certdata)
        self.ca_key_obj = self._try_load_key(keydata)

        # also store PEM versions in memory for future use if needed
        self.ca_cert_pem = self.ca_cert_obj.public_bytes(serialization.Encoding.PEM)
        self.ca_key_pem = self.ca_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def _is_ip(self, name: str) -> bool:
        try:
            ipaddress.ip_address(name)
            return True
        except Exception:
            return False

    def get_cert_for(self, common_name: str) -> Tuple[str, str]:
        # Return (cert_pem_path, key_pem_path) for the hostname.
        now = time.time()
        cached = self._cert_cache.get(common_name)
        if cached and cached[2] > now:
            return cached[0], cached[1]

        # Generate 2048 RSA key
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        issuer = self.ca_cert_obj.subject
        serial = x509.random_serial_number()
        not_before = datetime.datetime.utcnow() - datetime.timedelta(minutes=1)
        not_after = datetime.datetime.utcnow() + datetime.timedelta(days=365)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(leaf_key.public_key())
        builder = builder.serial_number(serial)
        builder = builder.not_valid_before(not_before)
        builder = builder.not_valid_after(not_after)

        # SAN
        try:
            if self._is_ip(common_name):
                builder = builder.add_extension(SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(common_name))]), critical=False)
            else:
                builder = builder.add_extension(SubjectAlternativeName([DNSName(common_name)]), critical=False)
        except Exception:
            pass

        # basic constraints
        builder = builder.add_extension(BasicConstraints(ca=False, path_length=None), critical=True)

        cert = builder.sign(private_key=self.ca_key_obj, algorithm=hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        cert_file.write(cert_pem); cert_file.flush(); cert_file.close()
        key_file.write(key_pem); key_file.flush(); key_file.close()

        self._cert_cache[common_name] = (cert_file.name, key_file.name, now + 300)
        return cert_file.name, key_file.name

    def cleanup(self):
        for val in list(self._cert_cache.values()):
            for path in val[:2]:
                try: os.unlink(path)
                except: pass
        self._cert_cache.clear()

# -----------------------
# Simple HTTP helpers (blocking)
# -----------------------
def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data

def recv_http_message(sock: socket.socket, initial: bytes = b"") -> bytes:
    """
    Blocking read: read headers until \r\n\r\n, then read Content-Length if present.
    Returns the full bytes (headers+body).
    """
    data = initial
    # read header
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    if b"\r\n\r\n" not in data:
        return data
    head, rest = data.split(b"\r\n\r\n", 1)
    headers_text = head.decode(errors="ignore")
    m = re.search(r'Content-Length:\s*(\d+)', headers_text, re.IGNORECASE)
    if m:
        length = int(m.group(1))
        if len(rest) >= length:
            return head + b"\r\n\r\n" + rest[:length]
        # need to read more
        body = rest
        toread = length - len(body)
        if toread > 0:
            body += recv_exact(sock, toread)
        return head + b"\r\n\r\n" + body
    else:
        # no content-length -> just return headers (for many GETs, that's enough)
        return head + b"\r\n\r\n" + rest

def parse_host_port_from_request_head(head_bytes: bytes) -> Tuple[str, int]:
    head = head_bytes.decode(errors="ignore")
    # try Host: header
    for line in head.splitlines():
        if line.lower().startswith("host:"):
            host_val = line.split(":", 1)[1].strip()
            if ":" in host_val:
                h, p = host_val.rsplit(":", 1)
                try:
                    return h, int(p)
                except:
                    return host_val, 80
            return host_val, 80
    # fallback try request URL (absolute-form)
    first_line = head.splitlines()[0]
    parts = first_line.split()
    if len(parts) >= 2:
        url = parts[1]
        if url.startswith("http://") or url.startswith("https://"):
            try:
                _, rest = url.split("://", 1)
                hostport, _ = rest.split("/", 1) if "/" in rest else (rest, "")
                if ":" in hostport:
                    h, p = hostport.split(":", 1)
                    return h, int(p)
                return hostport, 80
            except:
                pass
    raise ValueError("Host header not found")

def fix_request_line(raw_request_bytes):
    lines = raw_request_bytes.split(b'\r\n')
    request_line = lines[0].decode(errors='replace')
    parts = request_line.split(' ')
    if len(parts) != 3:
        # malformed request, just return as-is
        return raw_request_bytes
    method, full_url, version = parts

    from urllib.parse import urlparse
    parsed = urlparse(full_url)

    # Build new request line with relative path + query
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query
    new_request_line = f"{method} {path} {version}".encode()

    # Replace the first line with new_request_line
    lines[0] = new_request_line

    # Rejoin lines to bytes, preserving rest of request
    fixed_request = b'\r\n'.join(lines)
    return fixed_request

# -----------------------
# Worker for each client connection (threaded)
# -----------------------
class ProxyWorker(threading.Thread):
    def __init__(self, client_sock: socket.socket, addr, ca_provider: CAProvider, gui_queue: Queue, intercept_flag: threading.Event, tx_counter_ref):
        super().__init__(daemon=True)
        self.client_sock = client_sock
        self.client_addr = addr
        self.ca = ca_provider
        self.gui_queue = gui_queue
        self.intercept_flag = intercept_flag
        self.tx_counter_ref = tx_counter_ref

    def run(self):
        try:
            self.handle()
        except Exception:
            print("Worker exception:")
            traceback.print_exc()
        finally:
            try: self.client_sock.close()
            except: pass

    def handle(self):
        client = self.client_sock
        # read first line + headers to detect CONNECT or normal request
        try:
            client.settimeout(5.0)
            initial = b""
            while b"\r\n" not in initial:
                chunk = client.recv(4096)
                if not chunk:
                    return
                initial += chunk
            # read rest of headers
            while b"\r\n\r\n" not in initial:
                chunk = client.recv(4096)
                if not chunk:
                    break
                initial += chunk
            client.settimeout(None)
        except socket.timeout:
            return

        if not initial:
            return
        first_line = initial.split(b"\r\n", 1)[0].decode(errors="ignore")
        if first_line.upper().startswith("CONNECT"):
            # HTTPS CONNECT: format CONNECT host:port HTTP/1.1
            try:
                parts = first_line.split()
                target = parts[1]
                if ":" in target:
                    host, port_s = target.split(":", 1)
                    port = int(port_s)
                else:
                    host, port = target, 443
            except Exception:
                return
            # reply OK
            try:
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            except Exception:
                return

            # Now wrap client socket with server-side TLS using generated cert for host
            cert_path, key_path = self.ca.get_cert_for(host)
            import ssl
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            # Wrap - perform handshake
            try:
                client_ssl = server_ctx.wrap_socket(client, server_side=True)
            except Exception as e:
                print("TLS wrap_socket (server) failed:", e)
                return

            # Connect to upstream with TLS
            try:
                upstream_raw = socket.create_connection((host, port), timeout=6)
                client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                client_ctx.load_verify_locations(cadata=self.ca.ca_cert_pem.decode('utf-8'))
                client_ctx.check_hostname = True
                client_ctx.verify_mode = ssl.CERT_REQUIRED
                upstream = client_ctx.wrap_socket(upstream_raw, server_hostname=host)
            except ssl.SSLError as e:
                print(f"Upstream TLS connect failed with verification error: {e}, retrying without verification")
                try:
                    upstream_raw = socket.create_connection((host, port), timeout=6)
                    client_ctx = ssl.create_default_context()
                    client_ctx.check_hostname = False
                    client_ctx.verify_mode = ssl.CERT_NONE
                    upstream = client_ctx.wrap_socket(upstream_raw, server_hostname=host)
                except Exception as e2:
                    print(f"Upstream TLS connect failed again: {e2}")
                    raise e2

            # Now we have decrypted sides: client_ssl <--> upstream
            self.mitm_exchange(client_ssl, upstream, host, port, is_tls=True)
            try:
                client_ssl.close()
            except: pass
            try:
                upstream.close()
            except: pass
        else:
            # Plain HTTP: we already have initial bytes; handle as normal HTTP connection
            try:
                head = initial
                host, port = parse_host_port_from_request_head(head)
            except Exception:
                return
            # open upstream plain socket
            try:
                upstream = socket.create_connection((host, port), timeout=6)
            except Exception as e:
                print("Upstream connect failed:", e)
                try: upstream.close()
                except: pass
                return
            # interact: read full request (including body if Content-Length)
            req = recv_http_message(client, initial=head)
            req = fix_request_line(req)
            # create transaction
            txid = self.tx_counter_ref['v']
            self.tx_counter_ref['v'] += 1
            tx = Transaction(id=txid, host=host, port=port, request_raw=req)
            # notify GUI
            self.gui_queue.put(("new_tx", tx))
            # intercept if enabled
            if self.intercept_flag.is_set():
                tx.intercepted_request = True
                tx.status = "waiting_request"
                self.gui_queue.put(("update_tx", tx))
                tx.request_event.wait()  # GUI sets event when forwarded
            # send request upstream
            upstream.sendall(tx.request_raw)
            # get response
            resp = recv_http_message(upstream)
            tx.response_raw = resp
            tx.response_ready = True
            if self.intercept_flag.is_set():
                tx.intercepted_response = True
                tx.status = "waiting_response"
                self.gui_queue.put(("update_tx", tx))
                tx.response_event.wait()
            # send back to client
            try:
                client.sendall(tx.response_raw)
            except:
                pass
            tx.status = "forwarded"
            self.gui_queue.put(("update_tx", tx))
            try: upstream.close()
            except: pass

    def mitm_exchange(self, client_sock: socket.socket, upstream_sock: socket.socket, host: str, port: int, is_tls: bool):
        """
        Read requests from client_sock, forward to upstream_sock, capture responses,
        and allow GUI to intercept/modify using Transaction objects + events.
        This function runs in this worker's thread.
        """

        client = client_sock
        upstream = upstream_sock
        # We'll loop: client -> upstream (requests), upstream -> client (responses)
        # For simplicity, handle one request at a time in sequence.
        while True:
            try:
                req = recv_http_message(client)
                req = fix_request_line(req)
            except Exception:
                break
            if not req:
                break

            txid = self.tx_counter_ref['v']; self.tx_counter_ref['v'] += 1
            tx = Transaction(id=txid, host=host, port=port, request_raw=req)
            self.gui_queue.put(("new_tx", tx))

            # Wait for GUI forward if intercept enabled
            if self.intercept_flag.is_set():
                tx.intercepted_request = True
                tx.status = "waiting_request"
                self.gui_queue.put(("update_tx", tx))
                tx.request_event.wait()

            # send to upstream
            try:
                upstream.sendall(tx.request_raw)
            except Exception:
                break

            # read response
            try:
                resp = recv_http_message(upstream)
            except Exception:
                break

            tx.response_raw = resp
            tx.response_ready = True
            if self.intercept_flag.is_set():
                tx.intercepted_response = True
                tx.status = "waiting_response"
                self.gui_queue.put(("update_tx", tx))
                tx.response_event.wait()

            # send back to client
            try:
                client.sendall(tx.response_raw)
            except Exception:
                break

            tx.status = "forwarded"
            self.gui_queue.put(("update_tx", tx))

        # done
        try:
            client.close()
        except: pass
        try:
            upstream.close()
        except: pass

# -----------------------
# Main Server Thread
# -----------------------
class ProxyServer(threading.Thread):
    def __init__(self, listen_addr: Tuple[str, int], ca_provider: CAProvider, gui_queue: Queue):
        super().__init__(daemon=True)
        self.listen_addr = listen_addr
        self.ca = ca_provider
        self.gui_queue = gui_queue
        self.intercept_flag = threading.Event()
        # self.intercept_flag.set()  # default OFF
        self._shutdown = threading.Event()
        self.tx_counter_ref = {'v': 1}
        self._sock = None

    def set_intercept(self, val: bool):
        if val:
            self.intercept_flag.set()
        else:
            self.intercept_flag.clear()

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(self.listen_addr)
        s.listen(200)
        self._sock = s
        print(f"Listening on {host}:{port_s}")
        while not self._shutdown.is_set():
            try:
                client, addr = s.accept()
                worker = ProxyWorker(client, addr, self.ca, self.gui_queue, self.intercept_flag, self.tx_counter_ref)
                worker.start()
            except Exception as e:
                # can happen during shutdown
                if not self._shutdown.is_set():
                    print("Accept error:", e)
        try:
            s.close()
        except: pass

    def shutdown(self):
        self._shutdown.set()
        try:
            if self._sock:
                self._sock.close()
        except: pass

# -----------------------
# GUI (PyQt5)
# -----------------------
class ProxyGUI(QtWidgets.QMainWindow):
    def __init__(self, server: ProxyServer, gui_queue: Queue, ca_provider: CAProvider):
        super().__init__()
        self.server = server
        self.gui_queue = gui_queue
        self.ca = ca_provider
        self.setWindowTitle(f"MITM Proxy (threaded) - Listening on {host}:{port_s}")
        self.resize(1100, 700)
        self.transactions = {}  # id -> Transaction
        self._build_ui()
        # timer to poll queue
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self._process_queue)
        self.timer.start(100)

    def _build_ui(self):
        w = QtWidgets.QWidget()
        self.setCentralWidget(w)
        layout = QtWidgets.QHBoxLayout(w)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)

        # ----- Left: transaction list -----
        left = QtWidgets.QVBoxLayout()
        topbar = QtWidgets.QHBoxLayout()
        self.intercept_btn = QtWidgets.QPushButton("Intercept: OFF")
        self.intercept_btn.setCheckable(True)
        self.intercept_btn.setChecked(False)
        self.intercept_btn.clicked.connect(self.toggle_intercept)
        topbar.addWidget(self.intercept_btn)
        topbar.addStretch()
        left.addLayout(topbar)

        self.tx_list = QtWidgets.QListWidget()
        self.tx_list.setFont(QtGui.QFont("Consolas", 10))
        self.tx_list.itemSelectionChanged.connect(self.on_tx_select)
        left.addWidget(self.tx_list)
        layout.addLayout(left, 3)

        # ----- Right: request/response tabs -----
        right = QtWidgets.QVBoxLayout()
        self.tab = QtWidgets.QTabWidget()

        # Request tab
        self.req_widget = QtWidgets.QWidget()
        req_layout = QtWidgets.QVBoxLayout(self.req_widget)

        # Controls for request
        req_controls = QtWidgets.QHBoxLayout()
        self.req_hex_btn = QtWidgets.QPushButton("Hex View")
        self.req_hex_btn.setCheckable(True)
        self.req_hex_btn.toggled.connect(self.toggle_req_hex)
        req_controls.addWidget(self.req_hex_btn)

        self.req_forward_btn = QtWidgets.QPushButton("Forward Request")
        self.req_forward_btn.clicked.connect(self.forward_request)
        req_controls.addStretch()
        req_controls.addWidget(self.req_forward_btn)
        req_layout.addLayout(req_controls)

        # Request editors
        req_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.req_text = QtWidgets.QPlainTextEdit()
        self.req_text.setFont(QtGui.QFont("Consolas", 10))
        self.req_hex = QtWidgets.QPlainTextEdit()
        self.req_hex.setFont(QtGui.QFont("Consolas", 10))
        req_splitter.addWidget(self.req_text)
        req_splitter.addWidget(self.req_hex)
        req_layout.addWidget(req_splitter)
        self.tab.addTab(self.req_widget, "Request")

        # Response tab
        self.resp_widget = QtWidgets.QWidget()
        resp_layout = QtWidgets.QVBoxLayout(self.resp_widget)

        resp_controls = QtWidgets.QHBoxLayout()
        self.resp_hex_btn = QtWidgets.QPushButton("Hex View")
        self.resp_hex_btn.setCheckable(True)
        self.resp_hex_btn.toggled.connect(self.toggle_resp_hex)
        resp_controls.addWidget(self.resp_hex_btn)

        self.resp_forward_btn = QtWidgets.QPushButton("Forward Response")
        self.resp_forward_btn.clicked.connect(self.forward_response)
        resp_controls.addStretch()
        resp_controls.addWidget(self.resp_forward_btn)
        resp_layout.addLayout(resp_controls)

        resp_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.resp_text = QtWidgets.QPlainTextEdit()
        self.resp_text.setFont(QtGui.QFont("Consolas", 10))
        self.resp_hex = QtWidgets.QPlainTextEdit()
        self.resp_hex.setFont(QtGui.QFont("Consolas", 10))
        resp_splitter.addWidget(self.resp_text)
        resp_splitter.addWidget(self.resp_hex)
        resp_layout.addWidget(resp_splitter)
        self.tab.addTab(self.resp_widget, "Response")

        right.addWidget(self.tab)
        self.status_label = QtWidgets.QLabel("Ready")
        right.addWidget(self.status_label)
        layout.addLayout(right, 7)

        # guards to avoid recursion
        self._updating_req = False
        self._updating_resp = False

        # Connect text changed for request editors
        self.req_text.textChanged.connect(self._req_text_changed)
        self.req_hex.textChanged.connect(self._req_hex_changed)

        # Connect selection changed for request editors
        self.req_text.cursorPositionChanged.connect(self._req_text_selection_changed)
        self.req_hex.cursorPositionChanged.connect(self._req_hex_selection_changed)

        # Connect text changed for response editors
        self.resp_text.textChanged.connect(self._resp_text_changed)
        self.resp_hex.textChanged.connect(self._resp_hex_changed)

        # Connect selection changed for response editors
        self.resp_text.cursorPositionChanged.connect(self._resp_text_selection_changed)
        self.resp_hex.cursorPositionChanged.connect(self._resp_hex_selection_changed)

        self.sort_asc = False  # descending by default

        # Setup button and connect
        self.sort_btn = QtWidgets.QPushButton("Sort ASC")
        self.sort_btn.clicked.connect(self.toggle_sort)
        topbar.addWidget(self.sort_btn)

    def toggle_sort(self):
        self.sort_asc = not self.sort_asc
        self.sort_btn.setText("Sort ASC" if self.sort_asc else "Sort DESC")
        self._resort_tx_list()

    def _resort_tx_list(self):
        self.tx_list.clear()
        tx_ids = sorted(self.transactions.keys(), reverse=not self.sort_asc)
        for txid in tx_ids:
            tx = self.transactions[txid]
            it = QtWidgets.QListWidgetItem(f"#{tx.id} {tx.host}:{tx.port} [{tx.status}]")
            it.setData(QtCore.Qt.UserRole, tx.id)
            self.tx_list.addItem(it)  # append bottom for ascending

    def _add_tx(self, tx: Transaction):
        self.transactions[tx.id] = tx
        it = QtWidgets.QListWidgetItem(f"#{tx.id} {tx.host}:{tx.port} [{tx.status}]")
        it.setData(QtCore.Qt.UserRole, tx.id)
        # Insert item according to sort order:
        if self.sort_asc:
            self.tx_list.addItem(it)  # append bottom for ascending
        else:
            self.tx_list.insertItem(0, it)  # insert top for descending

    def _update_tx(self, tx: Transaction):
        for i in range(self.tx_list.count()):
            it = self.tx_list.item(i)
            if it.data(QtCore.Qt.UserRole) == tx.id:
                it.setText(f"#{tx.id} {tx.host}:{tx.port} [{tx.status}]")
                break



    def _req_text_selection_changed(self):
        if self._updating_req:
            return
        self._updating_req = True
        try:
            cursor = self.req_text.textCursor()
            start = cursor.selectionStart()
            end = cursor.selectionEnd()

            # Map raw text selection to hex view positions:
            # Each byte => 3 characters in hex view ("XX ")
            # So hex_start = start * 3, hex_end = end * 3 - 1 (because last byte no trailing space)
            hex_start = start * 3
            hex_end = end * 3 - 1

            hex_cursor = self.req_hex.textCursor()
            if hex_start >= 0:
                hex_cursor.setPosition(hex_start)
            if hex_end >= 0:
                hex_cursor.setPosition(hex_end, QtGui.QTextCursor.KeepAnchor)
            self.req_hex.setTextCursor(hex_cursor)
        finally:
            self._updating_req = False

    def _req_hex_selection_changed(self):
        if self._updating_req:
            return
        self._updating_req = True
        try:
            cursor = self.req_hex.textCursor()
            start = cursor.selectionStart()
            end = cursor.selectionEnd()

            # Map hex selection back to raw text:
            # Each byte is represented by 2 hex chars plus 1 space, so every 3 chars
            # Ignore spaces/newlines; count how many hex bytes before start
            hex_text = self.req_hex.toPlainText()
            # Count how many valid hex digits before start
            valid_pos = 0
            byte_start = 0
            byte_end = 0
            count = 0
            for i, c in enumerate(hex_text):
                if c in "0123456789abcdefABCDEF":
                    count += 1
                if count // 2 == 0 and i >= start:
                    byte_start = 0
                    break
                if count // 2 == (start // 3):
                    byte_start = count // 2
                if i >= start:
                    break
            # Rough estimate: use start//3 and end//3 for byte indexes
            raw_start = start // 3
            raw_end = max(end // 3, raw_start)

            raw_cursor = self.req_text.textCursor()
            if raw_start >= 0:
                raw_cursor.setPosition(raw_start)
            if raw_end >= 0:
                raw_cursor.setPosition(raw_end, QtGui.QTextCursor.KeepAnchor)
            self.req_text.setTextCursor(raw_cursor)
        finally:
            self._updating_req = False

    def _resp_text_selection_changed(self):
        if self._updating_resp:
            return
        self._updating_resp = True
        try:
            cursor = self.resp_text.textCursor()
            start = cursor.selectionStart()
            end = cursor.selectionEnd()

            hex_start = start * 3
            hex_end = end * 3 - 1

            hex_cursor = self.resp_hex.textCursor()
            if hex_start >= 0:
                hex_cursor.setPosition(hex_start)
            if hex_end >= 0:
                hex_cursor.setPosition(hex_end, QtGui.QTextCursor.KeepAnchor)
            self.resp_hex.setTextCursor(hex_cursor)
        finally:
            self._updating_resp = False

    def _resp_hex_selection_changed(self):
        if self._updating_resp:
            return
        self._updating_resp = True
        try:
            cursor = self.resp_hex.textCursor()
            start = cursor.selectionStart()
            end = cursor.selectionEnd()

            raw_start = start // 3
            raw_end = max(end // 3, raw_start)

            raw_cursor = self.resp_text.textCursor()
            
            if raw_start >= 0:
                raw_cursor.setPosition(raw_start)
            
            if raw_end >= 0:
                raw_cursor.setPosition(raw_end, QtGui.QTextCursor.KeepAnchor)
            self.resp_text.setTextCursor(raw_cursor)
        finally:
            self._updating_resp = False


    def _req_text_changed(self):
        if self._updating_req:
            return
        self._updating_req = True
        try:
            self.req_hex.setPlainText(bytes_to_hex_view(self.req_text.toPlainText().encode()))
        finally:
            self._updating_req = False

    def _req_hex_changed(self):
        if self._updating_req:
            return
        self._updating_req = True
        try:
            try:
                b = hex_view_to_bytes(self.req_hex.toPlainText())
                self.req_text.setPlainText(b.decode(errors="replace"))
            except Exception:
                pass
        finally:
            self._updating_req = False

    def _resp_text_changed(self):
        if self._updating_resp:
            return
        self._updating_resp = True
        try:
            self.resp_hex.setPlainText(bytes_to_hex_view(self.resp_text.toPlainText().encode()))
        finally:
            self._updating_resp = False

    def _resp_hex_changed(self):
        if self._updating_resp:
            return
        self._updating_resp = True
        try:
            try:
                b = hex_view_to_bytes(self.resp_hex.toPlainText())
                self.resp_text.setPlainText(b.decode(errors="replace"))
            except Exception:
                pass
        finally:
            self._updating_resp = False


    def toggle_intercept(self):
        enabled = self.intercept_btn.isChecked()
        self.intercept_btn.setText("Intercept: ON" if enabled else "Intercept: OFF")
        self.server.set_intercept(enabled)
        self.status_label.setText("Intercept " + ("enabled" if enabled else "disabled"))

        if not enabled:  # If turning intercept OFF
            for txid, tx in self.transactions.items():
                with tx.lock:
                    if tx.status == "waiting_request":
                        tx.status = "forwarded"
                        # Trigger any events or update queue if necessary
                        # For example, if tx has an event for forwarding request:
                        if hasattr(tx, "request_event"):
                            tx.request_event.set()
                        self._update_tx(tx)


    def _process_queue(self):
        try:
            while True:
                item = self.gui_queue.get_nowait()
                typ, obj = item
                if typ == "new_tx":
                    self._add_tx(obj)
                elif typ == "update_tx":
                    self._update_tx(obj)
        except Empty:
            pass

    """
    def _add_tx(self, tx: Transaction):
        self.transactions[tx.id] = tx
        it = QtWidgets.QListWidgetItem(f"#{tx.id} {tx.host}:{tx.port} [{tx.status}]")
        it.setData(QtCore.Qt.UserRole, tx.id)
        self.tx_list.addItem(it)

    def _update_tx(self, tx: Transaction):
        # update existing listing
        for i in range(self.tx_list.count()):
            it = self.tx_list.item(i)
            if it.data(QtCore.Qt.UserRole) == tx.id:
                it.setText(f"#{tx.id} {tx.host}:{tx.port} [{tx.status}]")
                break
    """

    def on_tx_select(self):
        sel = self.tx_list.selectedItems()
        if not sel:
            return
        txid = sel[0].data(QtCore.Qt.UserRole)
        tx = self.transactions.get(txid)
        if not tx:
            return
        # load panes
        try:
            self.req_text.setPlainText(tx.request_raw.decode(errors="replace"))
        except:
            self.req_text.setPlainText("")
        self.req_hex.setPlainText(bytes_to_hex_view(tx.request_raw))
        try:
            self.resp_text.setPlainText(tx.response_raw.decode(errors="replace"))
        except:
            self.resp_text.setPlainText("")
        self.resp_hex.setPlainText(bytes_to_hex_view(tx.response_raw))

    def toggle_req_hex(self):
        show = self.req_hex_btn.isChecked()
        self.req_hex.setVisible(show); self.req_text.setVisible(not show)

    def toggle_resp_hex(self):
        show = self.resp_hex_btn.isChecked()
        self.resp_hex.setVisible(show); self.resp_text.setVisible(not show)

    def get_selected_tx(self) -> Optional[Transaction]:
        sel = self.tx_list.selectedItems()
        if not sel:
            return None
        txid = sel[0].data(QtCore.Qt.UserRole)
        return self.transactions.get(txid)

    def forward_request(self):
        tx = self.get_selected_tx()
        if not tx:
            self.status_label.setText("No transaction selected")
            return
        # get bytes from pane
        if self.req_hex_btn.isChecked():
            try:
                newb = hex_view_to_bytes(self.req_hex.toPlainText())
            except Exception as e:
                self.status_label.setText("Invalid hex")
                return
        else:
            newb = self.req_text.toPlainText().encode()
        with tx.lock:
            tx.request_raw = newb
            tx.request_event.set()
            tx.status = "req_forwarded"
        self._update_tx(tx)
        self.status_label.setText(f"Request #{tx.id} forwarded")

    def forward_response(self):
        tx = self.get_selected_tx()
        if not tx:
            self.status_label.setText("No transaction selected")
            return
        if self.resp_hex_btn.isChecked():
            try:
                newb = hex_view_to_bytes(self.resp_hex.toPlainText())
            except Exception:
                self.status_label.setText("Invalid hex")
                return
        else:
            newb = self.resp_text.toPlainText().encode()
        with tx.lock:
            tx.response_raw = newb
            tx.response_event.set()
            tx.status = "resp_forwarded"
        self._update_tx(tx)
        self.status_label.setText(f"Response #{tx.id} forwarded")

# -----------------------
# Entrypoint
# -----------------------
def main():
    global host
    global port_s
    parser = argparse.ArgumentParser()
    parser.add_argument("--ca-cert", required=True, help="CA cert (DER or PEM)")
    parser.add_argument("--ca-key", required=True, help="CA private key (DER or PEM)")
    parser.add_argument("--listen", default="127.0.0.1:8080", help="listen address host:port")
    args = parser.parse_args()

    host, port_s = args.listen.split(":", 1)
    port = int(port_s)

    ca = CAProvider(args.ca_cert, args.ca_key)
    gui_queue = Queue()
    server = ProxyServer((host, port), ca, gui_queue)
    server.start()

    app = QtWidgets.QApplication(sys.argv)
    gui = ProxyGUI(server, gui_queue, ca)
    gui.show()

    try:
        sys.exit(app.exec_())
    finally:
        server.shutdown()
        ca.cleanup()

if __name__ == "__main__":
    main()
