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

import ipaddress
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
import traceback
import ssl

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


global inject
global inject_search_input
global inject_payload_input


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

"""
def bytes_to_hex_view(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)
"""

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
    request_method: str = ""
    request_path: str = ""

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

    def _connect_upstream_tls(self, host: str, port: int):
        """Connect to upstream over TLS:
           - First try verify with our CA (self.ca.ca_cert_pem)
           - If that fails, retry with CERT_NONE + no hostname check.
           Returns an SSL-wrapped socket.
        """
        import ssl

        # Create bare TCP first
        upstream_raw = socket.create_connection((host, port), timeout=6)

        try:
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            # trust our CA first
            ctx.load_verify_locations(cadata=self.ca.ca_cert_pem.decode('utf-8'))
            # SNI only for hostnames (not IPs)
            try:
                ipaddress.ip_address(host)
                is_ip = True
            except ValueError:
                is_ip = False

            ctx.check_hostname = not is_ip
            server_hostname = None if is_ip else host
            upstream = ctx.wrap_socket(upstream_raw, server_hostname=server_hostname)
            return upstream
        except Exception as e:
            # fallback: no-verify
            try:
                upstream_raw.close()
            except:
                pass

            upstream_raw2 = socket.create_connection((host, port), timeout=6)
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            upstream = ctx2.wrap_socket(upstream_raw2, server_hostname=None)
            return upstream

    """
    def _do_inject_before_send_upstream(self, tx_request_raw):
        if not inject:
            return tx_request_raw
            
        # payload = b"DEAD'; WAIT FOR DELAY '0:0:10';-- -"
        # payload = b"REPLACEME123"
        # payload = "REPLACEME12345".encode('utf-8')
        # payload = b"REPLACEME123"
        
        search = inject_search_input.text().encode()
        payload = inject_payload_input.text().encode()
        
        payload_len = len(payload)

        data = bytearray(tx_request_raw)  # work on bytes
        pos = 0
        while True:
            idx = data.find(search, pos)
            if idx == -1:
                break
            if idx > 0:
                data[idx - 1] = payload_len  # preceding length byte
            data = data[:idx] + payload + data[idx + len(search):]
            pos = idx + len(payload)

        tx_request_raw = bytes(data)
        return tx_request_raw
    """

    def _do_inject_before_send_downstream(self, resp):
        #if not inject:
        #    return resp
        
        
        # search = b"\x40\x06\x52\x6f\x6c\x65\x42\x45\x3f\x02\x49\x64\x8a\x62\x10\x40"
        # payload = b"\x40\x06\x52\x6f\x6c\x65\x42\x45\x3f\x02\x49\x64\x8a\x2d\x06\x40"
        #search = b"TEST"
        #payload = b"TEST12345"
        payload_len = len(payload)

        data = bytearray(resp)
        pos = 0
        while True:
            idx = data.find(search, pos)
            if idx == -1:
                break
            if idx > 0:
                data[idx - 1] = payload_len
            data = data[:idx] + payload + data[idx + len(search):]
            pos = idx + len(payload)

        # Update Content-Length if present
        headers_end = data.find(b"\r\n\r\n")
        if headers_end != -1:
            headers = data[:headers_end]
            body = data[headers_end + 4:]
            new_length = str(len(body)).encode()  # keep as bytes

            # Use \g<1> for proper backreference
            headers = re.sub(rb"(Content-Length:\s*)\d+", rb"\g<1>" + new_length, headers, flags=re.IGNORECASE)

            data = headers + b"\r\n\r\n" + body
        
        return bytes(data) 
    
    def _do_inject_before_send_upstream(self, tx_request_raw):
        if not inject:
            return tx_request_raw

        search = inject_search_input.text().encode()
        payload = inject_payload_input.text().encode()
        payload_len = len(payload)

        data = bytearray(tx_request_raw)
        pos = 0
        while True:
            idx = data.find(search, pos)
            if idx == -1:
                break
            if idx > 0:
                data[idx - 1] = payload_len
            data = data[:idx] + payload + data[idx + len(search):]
            pos = idx + len(payload)

        # Update Content-Length if present
        headers_end = data.find(b"\r\n\r\n")
        if headers_end != -1:
            headers = data[:headers_end]
            body = data[headers_end + 4:]
            new_length = str(len(body)).encode()  # keep as bytes

            # Use \g<1> for proper backreference
            headers = re.sub(rb"(Content-Length:\s*)\d+", rb"\g<1>" + new_length, headers, flags=re.IGNORECASE)

            data = headers + b"\r\n\r\n" + body
        
        return bytes(data)


    def handle(self):
        client = self.client_sock

        # Read the initial headers
        try:
            client.settimeout(5.0)
            initial = b""
            while b"\r\n" not in initial:
                chunk = client.recv(4096)
                if not chunk:
                    return
                initial += chunk
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

        # ------------------- HTTPS (CONNECT) -------------------
        if first_line.upper().startswith("CONNECT"):
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

            # Reply OK to CONNECT
            try:
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            except Exception:
                return

            # Terminate TLS to the client using our leaf cert
            import ssl
            cert_path, key_path = self.ca.get_cert_for(host)
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            try:
                client_ssl = server_ctx.wrap_socket(client, server_side=True)
            except Exception as e:
                print("TLS wrap_socket (server) failed:", e)
                return

            # Connect upstream with verify-then-fallback
            try:
                upstream = self._connect_upstream_tls(host, port)
            except Exception as e:
                print("Upstream TLS connect failed:", e)
                try: client_ssl.close()
                except: pass
                return

            # Decrypted tunnel: client_ssl <-> upstream
            self.mitm_exchange(client_ssl, upstream, host, port, is_tls=True)
            try: client_ssl.close()
            except: pass
            try: upstream.close()
            except: pass
            return

        # ------------------- Plain HTTP -------------------
        try:
            head = initial
            host, port = parse_host_port_from_request_head(head)
        except Exception:
            return

        try:
            upstream = socket.create_connection((host, port), timeout=6)
        except Exception as e:
            print("Upstream connect failed:", e)
            try: upstream.close()
            except: pass
            return

        # Read full request (includes body if Content-Length)
        req = recv_http_message(client, initial=head)
        # If you have a fix_request_line(), keep it. If not, remove next line.
        try:
            req = fix_request_line(req)
        except NameError:
            pass

        # Create TX with method/path for list label
        txid = self.tx_counter_ref['v']; self.tx_counter_ref['v'] += 1
        fl = req.split(b'\r\n', 1)[0].decode(errors='ignore')
        parts = fl.split()
        method, path = (parts[0], parts[1]) if len(parts) >= 2 else ("-", "-")
        tx_request_raw = self._do_inject_before_send_upstream(req)
        tx = Transaction(id=txid, host=host, port=port, request_raw=tx_request_raw,
                         request_method=method, request_path=path)

        self.gui_queue.put(("new_tx", tx))

        # Intercept request if ON
        if self.intercept_flag.is_set():
            tx.intercepted_request = True
            tx.status = "waiting_request"
            self.gui_queue.put(("update_tx", tx))
            tx.request_event.wait()

        # Send upstream
        upstream.sendall(tx_request_raw)

        # Read response
        resp = recv_http_message(upstream)
        tx.response_raw = self._do_inject_before_send_downstream(resp)
        # tx.response_raw = resp
        tx.response_ready = True

        if self.intercept_flag.is_set():
            tx.intercepted_response = True
            tx.status = "waiting_response"
            # Tell GUI to populate Response tab right now
            self.gui_queue.put(("show_response", tx))
            # Optional also keep list updated
            self.gui_queue.put(("update_tx", tx))
            # Wait for GUI to edit and press "Forward Response"
            tx.response_event.wait()

        # Send back to client
        try:
            client.sendall(tx.response_raw)
        except:
            pass

        tx.status = "completed"
        self.gui_queue.put(("update_tx", tx))

        try: upstream.close()
        except: pass

    def mitm_exchange(self, client_sock: socket.socket, upstream_sock: socket.socket, host: str, port: int, is_tls: bool):
        client = client_sock
        upstream = upstream_sock

        while True:
            try:
                req = recv_http_message(client)
                try:
                    req = fix_request_line(req)
                except NameError:
                    pass
            except Exception:
                break
            if not req:
                break

            txid = self.tx_counter_ref['v']; self.tx_counter_ref['v'] += 1
            fl = req.split(b'\r\n', 1)[0].decode(errors='ignore')
            parts = fl.split()
            method, path = (parts[0], parts[1]) if len(parts) >= 2 else ("-", "-")

            tx_request_raw = self._do_inject_before_send_upstream(req)
            tx = Transaction(id=txid, host=host, port=port, request_raw=tx_request_raw,
                             request_method=method, request_path=path)
            self.gui_queue.put(("new_tx", tx))

            if self.intercept_flag.is_set():
                tx.intercepted_request = True
                tx.status = "waiting_request"
                self.gui_queue.put(("update_tx", tx))
                tx.request_event.wait()

            try:
                upstream.sendall(tx_request_raw)
            except Exception:
                break

            try:
                resp = recv_http_message(upstream)
            except Exception:
                break

            #tx.response_raw = resp
            tx.response_raw = self._do_inject_before_send_downstream(resp)
            tx.response_ready = True

            if self.intercept_flag.is_set():
                tx.intercepted_response = True
                tx.status = "waiting_response"
                self.gui_queue.put(("show_response", tx))  # <--- populate GUI
                self.gui_queue.put(("update_tx", tx))
                tx.response_event.wait()

            try:
                client.sendall(tx.response_raw)
            except Exception:
                break

            tx.status = "completed"
            self.gui_queue.put(("update_tx", tx))

        try: client.close()
        except: pass
        try: upstream.close()
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

class RepeaterWidget(QtWidgets.QWidget):
    """
    Burp-like repeater:
      - Tabs #1, #2, ...
      - Host/Port + Send per tab
      - Request/Response editors
      - Search bar at the BOTTOM of each editor
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        outer = QtWidgets.QVBoxLayout(self)
        self.repeater_tabs = QtWidgets.QTabWidget()
        self.repeater_tabs.setTabsClosable(True)
        self.repeater_tabs.tabCloseRequested.connect(self.repeater_tabs.removeTab)
        outer.addWidget(self.repeater_tabs)

    # ---------- public helpers ----------
    def send_into_first(self, host: str, port: int, req_bytes: bytes):
        """
        If tab #1 exists and its request editor is empty -> fill it.
        Else create a new tab.
        """
        if self.repeater_tabs.count() == 0:
            self.add_repeater_tab(host, port, req_bytes, make_active=False)
            return

        # Try to fill first if empty
        w = self.repeater_tabs.widget(0)
        req_edit = w.findChild(QtWidgets.QPlainTextEdit, "req_text")
        host_edit = w.findChild(QtWidgets.QLineEdit, "host_edit")
        port_edit = w.findChild(QtWidgets.QLineEdit, "port_edit")
        resp_edit = w.findChild(QtWidgets.QPlainTextEdit, "resp_text")

        if req_edit and (req_edit.toPlainText().strip() == ""):
            host_edit.setText(host)
            port_edit.setText(str(port))
            req_edit.setPlainText(req_bytes.decode(errors="ignore") if isinstance(req_bytes, bytes) else str(req_bytes))
            if resp_edit:
                resp_edit.clear()
        else:
            self.add_repeater_tab(host, port, req_bytes, make_active=False)

    def add_repeater_tab(self, host, port, req_data, make_active=True):
        repeater_inner = QtWidgets.QWidget()
        repeater_layout = QtWidgets.QVBoxLayout(repeater_inner)

        # Host/Port edit row
        host_port_layout = QtWidgets.QHBoxLayout()
        host_edit = QtWidgets.QLineEdit(host)
        port_edit = QtWidgets.QLineEdit(str(port))
        send_btn = QtWidgets.QPushButton("Send")
        send_btn.clicked.connect(lambda: self.send_repeater_request(host_edit, port_edit, self.req_text, self.resp_text))
        host_port_layout.addWidget(QtWidgets.QLabel("Host:"))
        host_port_layout.addWidget(host_edit)
        host_port_layout.addWidget(QtWidgets.QLabel("Port:"))
        host_port_layout.addWidget(port_edit)
        host_port_layout.addWidget(send_btn)
        repeater_layout.addLayout(host_port_layout)

        # Request editor + search bar
        self.req_text = QtWidgets.QPlainTextEdit()
        self.req_text.setFont(QtGui.QFont("Consolas", 10))
        self.req_text.setPlainText(req_data.decode(errors="replace") if isinstance(req_data, bytes) else req_data)
        self.req_hex = QtWidgets.QPlainTextEdit()
        self.req_hex.setFont(QtGui.QFont("Consolas", 10))
        self.req_hex.setPlainText(bytes_to_hex_view(req_data))

        
        req_splitter_top = QtWidgets.QWidget()
        req_splitter_top_layout = QtWidgets.QVBoxLayout(req_splitter_top)
        req_splitter_top_layout.addWidget(self.req_text)
        req_splitter_top_layout.addLayout(self._make_search_bar(self.req_text))

        req_splitter_bottom = QtWidgets.QWidget()
        req_splitter_bottom_layout = QtWidgets.QVBoxLayout(req_splitter_bottom)
        req_splitter_bottom_layout.addWidget(self.req_hex)
        req_splitter_bottom_layout.addLayout(self._make_search_bar(self.req_hex))

        splitter_inner = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        splitter_inner.addWidget(req_splitter_top)
        splitter_inner.addWidget(req_splitter_bottom)

        repeater_layout.addWidget(splitter_inner)

        # Response editor + search bar
        self.resp_text = QtWidgets.QPlainTextEdit()
        self.resp_text.setFont(QtGui.QFont("Consolas", 10))
        self.resp_text.setReadOnly(True)
        self.resp_hex = QtWidgets.QPlainTextEdit()
        self.resp_hex.setFont(QtGui.QFont("Consolas", 10))
        
        resp_splitter_top = QtWidgets.QWidget()
        resp_splitter_top_layout = QtWidgets.QVBoxLayout(resp_splitter_top)
        resp_splitter_top_layout.addWidget(self.resp_text)
        resp_splitter_top_layout.addLayout(self._make_search_bar(self.resp_text))

        resp_splitter_bottom = QtWidgets.QWidget()
        resp_splitter_bottom_layout = QtWidgets.QVBoxLayout(resp_splitter_bottom)
        resp_splitter_bottom_layout.addWidget(self.resp_hex)
        resp_splitter_bottom_layout.addLayout(self._make_search_bar(self.resp_hex))

        splitter_inner = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        splitter_inner.addWidget(resp_splitter_top)
        splitter_inner.addWidget(resp_splitter_bottom)

        repeater_layout.addWidget(splitter_inner)

        # Keyboard shortcut CTRL+R for resend
        shortcut = QtWidgets.QShortcut(QtGui.QKeySequence("Ctrl+R"), self.req_text)
        shortcut.activated.connect(lambda: self.add_repeater_tab(
            host_edit.text(),
            port_edit.text(),
            self.req_text.toPlainText().encode(),
            make_active=True
        ))

        
        # Recursion guards
        self._updating_req = False
        self._updating_resp = False

        # Connect request/response editor signals
        self.req_text.textChanged.connect(self._req_text_changed)
        self.req_hex.textChanged.connect(self._req_hex_changed)
        self.req_text.cursorPositionChanged.connect(self._req_text_selection_changed)
        self.req_hex.cursorPositionChanged.connect(self._req_hex_selection_changed)
        self.resp_text.textChanged.connect(self._resp_text_changed)
        self.resp_hex.textChanged.connect(self._resp_hex_changed)
        self.resp_text.cursorPositionChanged.connect(self._resp_text_selection_changed)
        self.resp_hex.cursorPositionChanged.connect(self._resp_hex_selection_changed)
        

        # Context menu "Send to Repeater"
        self.req_text.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        
        def repeater_context_menu(pos):
            menu = req_text.createStandardContextMenu()
            action = menu.addAction("Send to Repeater")
            action.triggered.connect(lambda: self.add_repeater_tab(host_edit.text(), port_edit.text(), self.req_text.toPlainText()))
            menu.exec_(self.req_text.mapToGlobal(pos))
        self.req_text.customContextMenuRequested.connect(repeater_context_menu)

        # Keyboard shortcut CTRL+Enter for resend (works when request editor is focused)
        send_shortcut = QtWidgets.QShortcut(QtGui.QKeySequence("Ctrl+Return"), self.req_text)
        send_shortcut.activated.connect(
            lambda: self.send_repeater_request(
                host_edit,
                port_edit,
                self.req_text,
                self.resp_text
            )
        )

        # Add tab
        idx = self.repeater_tabs.addTab(repeater_inner, f"#{self.repeater_tabs.count() + 1}")
        if make_active:
            self.repeater_tabs.setCurrentIndex(idx)
        return idx

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

    # ---------- internals ----------
    def _make_search_bar(self, editor: QtWidgets.QPlainTextEdit) -> QtWidgets.QHBoxLayout:
        """
        Bottom search bar for an editor. Enter/Next jumps to next match.
        """
        h = QtWidgets.QHBoxLayout()
        find_box = QtWidgets.QLineEdit()
        find_box.setPlaceholderText("Search…")
        next_btn = QtWidgets.QPushButton("Next")

        def find_next():
            pat = find_box.text()
            if not pat:
                return
            if not editor.find(pat):
                # wrap to start
                cur = editor.textCursor()
                cur.setPosition(0)
                editor.setTextCursor(cur)
                editor.find(pat)

        find_box.returnPressed.connect(find_next)
        next_btn.clicked.connect(find_next)

        h.addWidget(find_box)
        h.addWidget(next_btn)
        return h

    def send_repeater_request(self, host_edit, port_edit, req_text_edit, resp_text_edit):
        """
        Connect to host:port, optionally TLS (port 443), send request,
        read one response using recv_http_message(), ignore cert verification.
        """
        host = host_edit.text().strip()
        try:
            port = int(port_edit.text())
        except ValueError:
            resp_text_edit.setPlainText("Invalid port")
            return

        req_bytes = req_text_edit.toPlainText().encode()

        try:
            s = socket.create_connection((host, port), timeout=7)
            if port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=None)

            # send
            s.sendall(req_bytes)

            # read one HTTP message using your helper
            try:
                resp = recv_http_message(s)
            except Exception:
                # fallback: read until close
                resp = b""
                s.settimeout(2.0)
                try:
                    while True:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        resp += chunk
                except Exception:
                    pass

            s.close()
            resp_text_edit.setPlainText(resp.decode(errors="ignore"))
        except Exception as e:
            resp_text_edit.setPlainText(str(e))

# ---------------- Search Helper ----------------
def create_search_bar(edit_widget):
    search_layout = QtWidgets.QHBoxLayout()
    search_box = QtWidgets.QLineEdit()
    search_box.setPlaceholderText("Search...")
    next_btn = QtWidgets.QPushButton("Next")

    def do_search():
        text = search_box.text()
        if not text:
            return
        if not edit_widget.find(text):
            # If no match from current cursor, restart search from top
            cursor = edit_widget.textCursor()
            cursor.movePosition(QtGui.QTextCursor.Start)
            edit_widget.setTextCursor(cursor)
            edit_widget.find(text)

    next_btn.clicked.connect(do_search)
    search_box.returnPressed.connect(do_search)

    search_layout.addWidget(search_box)
    search_layout.addWidget(next_btn)
    return search_layout
            
# -----------------------
# GUI (PyQt5)
# -----------------------
from PyQt5 import QtWidgets, QtCore, QtGui
import socket, ssl
from queue import Queue

class ProxyGUI(QtWidgets.QMainWindow):
    def __init__(self, server, gui_queue: Queue, ca_provider, host, port):
        super().__init__()
        self.server = server
        self.gui_queue = gui_queue
        self.ca = ca_provider
        self.setWindowTitle(f"MITM Proxy (threaded) - Listening on {host}:{port}")
        self.resize(1600, 700)
        self.transactions = {}  # id -> Transaction
        self._build_ui()

        # Timer to poll queue
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self._process_queue)
        self.timer.start(100)

    def _build_ui(self):
        global inject
        # Main tab widget: Proxy / Repeater pages
        self.main_tab = QtWidgets.QTabWidget()
        self.setCentralWidget(self.main_tab)

        # ---------------- Proxy Page ----------------
        self.proxy_main_widget = QtWidgets.QWidget()
        proxy_layout = QtWidgets.QHBoxLayout(self.proxy_main_widget)
        proxy_layout.setContentsMargins(6, 6, 6, 6)
        proxy_layout.setSpacing(8)

        # Left: Transaction list
        left = QtWidgets.QVBoxLayout()
        topbar = QtWidgets.QHBoxLayout()
        
        # Intercept Button
        self.intercept_btn = QtWidgets.QPushButton("Intercept: OFF")
        self.intercept_btn.setCheckable(True)
        self.intercept_btn.setChecked(False)
        self.intercept_btn.clicked.connect(self.toggle_intercept)
        topbar.addWidget(self.intercept_btn)
        
        # Inject Button
        self.inject_btn = QtWidgets.QPushButton("Inject: OFF")
        self.inject_btn.setCheckable(True)
        self.inject_btn.setChecked(False)
        inject = False
        self.inject_btn.clicked.connect(self.toggle_inject)
        topbar.addWidget(self.inject_btn)

        topbar.addStretch()
        left.addLayout(topbar)

        self.tx_list = QtWidgets.QListWidget()
        self.tx_list.setFont(QtGui.QFont("Consolas", 10))
        self.tx_list.itemSelectionChanged.connect(self.on_tx_select)
        left.addWidget(self.tx_list)
        proxy_layout.addLayout(left, 3)

        # Right: Request/Response tabs
        right = QtWidgets.QVBoxLayout()
        self.tab = QtWidgets.QTabWidget()


        # ---------------- Main Tab: Request Tab ----------------
        self.req_widget = QtWidgets.QWidget()
        req_layout = QtWidgets.QVBoxLayout(self.req_widget)
        req_controls = QtWidgets.QHBoxLayout()
        self.req_forward_btn = QtWidgets.QPushButton("Forward Request")
        self.req_forward_btn.clicked.connect(self.forward_request)
        req_controls.addStretch()
        req_controls.addWidget(self.req_forward_btn)
        req_layout.addLayout(req_controls)

        global inject_search_input
        global inject_payload_input
        
        # Add inject input fields
        inject_layout = QtWidgets.QFormLayout()
        self.inject_search_input = QtWidgets.QLineEdit()
        self.inject_search_input.setPlaceholderText("Inject Search")
        self.inject_search_input.setText("REPLACEME123")
        inject_search_input = self.inject_search_input
        self.inject_payload_input = QtWidgets.QLineEdit()
        self.inject_payload_input.setPlaceholderText("Inject Payload")
        self.inject_payload_input.setText("REPLACEME123")
        inject_payload_input = self.inject_payload_input
        inject_layout.addRow("Search:", self.inject_search_input)
        inject_layout.addRow("Payload:", self.inject_payload_input)

        # Add this layout above the request editor
        inject_widget = QtWidgets.QWidget()
        inject_widget.setLayout(inject_layout)

        # Add inject inputs **below controls, above editors**
        req_layout.addWidget(inject_widget)

        # req_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        # Request editor
        self.req_text = QtWidgets.QPlainTextEdit()
        self.req_text.setFont(QtGui.QFont("Consolas", 10))
        self.req_hex = QtWidgets.QPlainTextEdit()
        self.req_hex.setFont(QtGui.QFont("Consolas", 10))

        req_splitter_top = QtWidgets.QWidget()
        req_splitter_top_layout = QtWidgets.QVBoxLayout(req_splitter_top)
        req_splitter_top_layout.addWidget(self.req_text)
        req_splitter_top_layout.addLayout(create_search_bar(self.req_text))

        req_splitter_bottom = QtWidgets.QWidget()
        req_splitter_bottom_layout = QtWidgets.QVBoxLayout(req_splitter_bottom)
        req_splitter_bottom_layout.addWidget(self.req_hex)
        req_splitter_bottom_layout.addLayout(create_search_bar(self.req_hex))

        splitter_inner = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        splitter_inner.addWidget(req_splitter_top)
        splitter_inner.addWidget(req_splitter_bottom)

        splitter_inner.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        req_splitter_top.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        req_splitter_bottom.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)


        req_layout.addWidget(splitter_inner)
        self.tab.addTab(self.req_widget, "Request")


        # ---------------- Main Tab: Response Tab ----------------
        self.resp_widget = QtWidgets.QWidget()
        resp_layout = QtWidgets.QVBoxLayout(self.resp_widget)
        resp_controls = QtWidgets.QHBoxLayout()
        self.resp_forward_btn = QtWidgets.QPushButton("Forward Response")
        self.resp_forward_btn.clicked.connect(self.forward_response)
        resp_controls.addStretch()
        resp_controls.addWidget(self.resp_forward_btn)
        resp_layout.addLayout(resp_controls)

        # Create editors
        self.resp_text = QtWidgets.QPlainTextEdit()
        self.resp_text.setFont(QtGui.QFont("Consolas", 10))

        self.resp_hex = QtWidgets.QPlainTextEdit()
        self.resp_hex.setFont(QtGui.QFont("Consolas", 10))

        # Add search bars
        resp_splitter_top = QtWidgets.QWidget()
        resp_splitter_top_layout = QtWidgets.QVBoxLayout(resp_splitter_top)
        resp_splitter_top_layout.addWidget(self.resp_text)
        resp_splitter_top_layout.addLayout(create_search_bar(self.resp_text))

        resp_splitter_bottom = QtWidgets.QWidget()
        resp_splitter_bottom_layout = QtWidgets.QVBoxLayout(resp_splitter_bottom)
        resp_splitter_bottom_layout.addWidget(self.resp_hex)
        resp_splitter_bottom_layout.addLayout(create_search_bar(self.resp_hex))

        # Combine text + hex in a splitter
        splitter_resp = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        splitter_resp.addWidget(resp_splitter_top)
        splitter_resp.addWidget(resp_splitter_bottom)

        resp_layout.addWidget(splitter_resp)
        self.tab.addTab(self.resp_widget, "Response")

        right.addWidget(self.tab)

        # Status label
        self.status_label = QtWidgets.QLabel("Ready")
        right.addWidget(self.status_label)
        proxy_layout.addLayout(right, 7)

        # Add Proxy page to main tab
        self.main_tab.addTab(self.proxy_main_widget, "Proxy")

        # ---------------- Repeater Page ----------------
        self.repeater_widget = RepeaterWidget()
        self.main_tab.addTab(self.repeater_widget, "Repeater")

        # Ctrl+R shortcut to send to repeater
        shortcut = QtWidgets.QShortcut(QtCore.Qt.CTRL + QtCore.Qt.Key_R, self.tx_list)
        shortcut.activated.connect(self.send_to_repeater)

        # Recursion guards
        self._updating_req = False
        self._updating_resp = False

        # Connect request/response editor signals
        self.req_text.textChanged.connect(self._req_text_changed)
        self.req_hex.textChanged.connect(self._req_hex_changed)
        self.req_text.cursorPositionChanged.connect(self._req_text_selection_changed)
        self.req_hex.cursorPositionChanged.connect(self._req_hex_selection_changed)
        self.resp_text.textChanged.connect(self._resp_text_changed)
        self.resp_hex.textChanged.connect(self._resp_hex_changed)
        self.resp_text.cursorPositionChanged.connect(self._resp_text_selection_changed)
        self.resp_hex.cursorPositionChanged.connect(self._resp_hex_selection_changed)

        # Sorting
        self.sort_asc = False
        self.sort_btn = QtWidgets.QPushButton("Sort ASC")
        self.sort_btn.clicked.connect(self.toggle_sort)
        topbar.addWidget(self.sort_btn)
        
        # Clear Transactions
        self.clear_btn = QtWidgets.QPushButton("Clear Transactions")
        self.clear_btn.clicked.connect(self.clear_transactions)
        topbar.addWidget(self.clear_btn)

        # Send to Repeater on TX List
        self.tx_list.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.tx_list.customContextMenuRequested.connect(self.proxy_list_context_menu)

        # Send to Repeater on Raw HTTP Request
        self.req_text.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.req_text.customContextMenuRequested.connect(self.show_req_context_menu)
        
        # Add Empty Repeater
        self.repeater_widget.add_repeater_tab("localhost", 443, "".encode(), make_active=False)

    def clear_transactions(self):
        """Clear all transactions from the list and internal storage."""
        self.tx_list.clear()
        self.transactions.clear()
        self.status_label.setText("Transactions cleared")
        
    def show_req_context_menu(self, pos):
        menu = self.req_text.createStandardContextMenu()
        menu.addSeparator()
        send_action = menu.addAction("Send to Repeater")

        action = menu.exec_(self.req_text.mapToGlobal(pos))
        if action == send_action:
            self.send_to_repeater()


    def proxy_list_context_menu(self, pos):
        menu = QtWidgets.QMenu()
        send_action = menu.addAction("Send to Repeater")
        action = menu.exec_(self.tx_list.mapToGlobal(pos))
        if action == send_action:
            self.send_to_repeater()


    # ---------------- Send to Repeater ----------------
    def send_to_repeater(self):
        item = self.tx_list.currentItem()
        if not item:
            return
        txid = int(item.text().split()[0][1:])
        tx = self.transactions.get(txid)
        if not tx:
            return
        # self.main_tab.setCurrentWidget(self.repeater_widget)
        self.repeater_widget.add_repeater_tab(tx.host, tx.port, tx.request_raw)


    def toggle_sort(self):
        self.sort_asc = not self.sort_asc
        self.sort_btn.setText("Sort ASC" if self.sort_asc else "Sort DESC")
        self._resort_tx_list()

    def toggle_inject(self):
        global inject
        
        enabled = self.inject_btn.isChecked()
        self.inject_btn.setText("Inject: ON" if enabled else "Inject: OFF")
        self.status_label.setText("Inject " + ("enabled" if enabled else "disabled"))
        
        inject = enabled

    def _resort_tx_list(self):
        self.tx_list.clear()
        tx_ids = sorted(self.transactions.keys(), reverse=not self.sort_asc)
        for txid in tx_ids:
            tx = self.transactions[txid]
            it = QtWidgets.QListWidgetItem(f"#{tx.id} {tx.host}:{tx.port} {tx.request_method} {tx.request_path} [{tx.status}]")
            it.setData(QtCore.Qt.UserRole, tx.id)
            self.tx_list.addItem(it)  # append bottom for ascending

    def _add_tx(self, tx: Transaction):
        self.transactions[tx.id] = tx
        it = QtWidgets.QListWidgetItem(f"#{tx.id} {tx.host}:{tx.port} {tx.request_method} {tx.request_path} [{tx.status}]")
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
                it.setText(f"#{tx.id} {tx.host}:{tx.port} {tx.request_method} {tx.request_path} [{tx.status}]")
                break

    def _show_response_tab(self, tx: Transaction):
        try:
            text_str = tx.response_raw.decode(errors="replace")
        except:
            text_str = ""
        self.resp_text.setPlainText(text_str)

        # If you have hex view
        self.resp_hex.setPlainText(
            ' '.join(f"{b:02x}" for b in tx.response_raw)
        )

        # Optionally auto-switch to the Response tab
        index = self.tab.indexOf(self.resp_widget)
        self.tab.setCurrentIndex(index)

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
                elif typ == "show_response":
                    self._show_response_tab(obj)
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

        # always take from req_text now
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

        # Always get from response editor
        edited_bytes = self.resp_text.toPlainText().encode()

        with tx.lock:
            tx.response_raw = edited_bytes  # Replace with edited response
            tx.response_event.set()         # Resume proxy thread
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
    gui = ProxyGUI(server, gui_queue, ca, host, port)
    gui.show()

    try:
        sys.exit(app.exec_())
    finally:
        server.shutdown()
        ca.cleanup()

if __name__ == "__main__":
    main()
