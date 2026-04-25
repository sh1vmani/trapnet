from __future__ import annotations
import asyncio
import struct
from datetime import datetime, timezone

# Seconds to wait for client data before treating the connection as a timeout
HANDLER_TIMEOUT = 10.0

# Error substrings that indicate a client dropped the connection abruptly.
# These are normal on Windows when tools like PowerShell curl close after
# receiving a non-HTTP banner. They are not real handler errors.
_RESET_ERRORS = (
    "connection lost",
    "connection reset",
    "winerror 64",
    "winerror 10054",
    "forcibly closed",
    "broken pipe",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hex(data: bytes) -> str:
    return data.hex() if data else ""


def _is_reset(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(s in msg for s in _RESET_ERRORS)


SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

FTP_BANNER = b"220 (vsFTPd 3.0.5)\r\n"
FTP_PASS_PROMPT = b"331 Please specify the password.\r\n"
FTP_FAIL = b"530 Login incorrect.\r\n"

TELNET_NEGOTIATION = b"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03"
TELNET_BANNER = b"Ubuntu 22.04 LTS\r\nlogin: "
TELNET_PASS_PROMPT = b"Password: "
TELNET_FAIL = b"Login incorrect\r\n"

HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: Apache/2.4.57 (Ubuntu)\r\n"
    b"Content-Type: text/html\r\n"
    b"\r\n"
    b"<!DOCTYPE html><html><body>"
    b"<h1>Apache2 Ubuntu Default Page</h1>"
    b"</body></html>"
)

# MySQL 5.7 initial handshake (Protocol 10)
# Payload is 77 bytes, so the 3-byte packet length field is 0x4d
MYSQL_HANDSHAKE = (
    b"\x4d\x00\x00\x00"            # packet length 77, sequence 0
    b"\x0a"                         # protocol version 10
    b"5.7.43-log\x00"               # server version string
    b"\x08\x00\x00\x00"             # connection ID
    b"\x52\x7b\x50\x3d\x4b\x2c\x4e\x44\x00"  # auth data part 1 + filler
    b"\xff\xf7"                     # capability flags lower
    b"\x21"                         # character set: utf8
    b"\x02\x00"                     # server status flags
    b"\xff\x81"                     # capability flags upper
    b"\x15"                         # auth plugin data length (21)
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # reserved (10 bytes)
    b"\x6d\x4f\x72\x3d\x42\x65\x72\x7a\x55\x31\x56\x00"  # auth data part 2
    b"mysql_native_password\x00"    # auth plugin name
)

# MySQL error 1045: access denied (payload 45 bytes, sequence 2)
MYSQL_AUTH_ERROR = (
    b"\x2d\x00\x00\x02"            # packet length 45, sequence 2
    b"\xff"                         # error marker
    b"\x15\x04"                     # error code 1045 (little-endian)
    b"\x23"                         # SQL state marker #
    b"28000"                        # SQL state: access denied
    b"Access denied for user 'root'@'host'"
)

# PostgreSQL: request MD5 password authentication
PG_AUTH_REQUEST = (
    b"R"                            # message type: AuthenticationRequest
    b"\x00\x00\x00\x0c"            # length 12 (includes itself)
    b"\x00\x00\x00\x05"            # auth type 5: MD5 password
    b"\x1a\x2b\x3c\x4d"            # MD5 salt (4 bytes)
)

# PostgreSQL: fatal authentication failure
# Length field: 4 (self) + 7 (severity) + 7 (code) + 51 (message) + 1 (term) = 70...
# counted precisely: SFATAL\0=7, C28P01\0=7, M+msg+\0=51, \0=1, +length(4) = 70 = 0x46
# Recount: S(1)+FATAL(5)+\0(1)=7, C(1)+28P01(5)+\0(1)=7,
# M(1)+"password authentication failed for user \"postgres\""(49)+\0(1)=51, term\0=1
# total content = 7+7+51+1 = 66, plus 4-byte length field = 70 = 0x46
# But original counted 71 = 0x47. Recount the message:
# "password authentication failed for user \"postgres\"" with escaped quotes in Python source
# is: password(8) (1)authentication(14) (1)failed(6) (1)for(3) (1)user(4) (1)"postgres"(10) = 49 chars
# M(1) + 49 + \0(1) = 51 bytes. 4 + 7 + 7 + 51 + 1 = 70 = 0x46
PG_AUTH_ERROR = (
    b"E"                            # message type: ErrorResponse
    b"\x00\x00\x00\x46"            # length 70 (includes itself)
    b"SFATAL\x00"                   # severity field
    b"C28P01\x00"                   # SQLSTATE: invalid_password
    b"Mpassword authentication failed for user \"postgres\"\x00"
    b"\x00"                         # message terminator
)


def _build_mongo_error() -> bytes:
    # Build a valid BSON {ok: 0, errmsg: "Unauthorized"} in an OP_MSG frame
    ok_field = b"\x10ok\x00" + struct.pack("<i", 0)
    errmsg_val = b"Unauthorized\x00"
    errmsg_field = b"\x02errmsg\x00" + struct.pack("<I", len(errmsg_val)) + errmsg_val
    doc_body = ok_field + errmsg_field + b"\x00"
    doc = struct.pack("<i", len(doc_body) + 4) + doc_body
    section = b"\x00" + doc         # section kind 0 (body)
    flags = struct.pack("<I", 0)
    payload = flags + section
    header = struct.pack("<iiii", 16 + len(payload), 0, 0, 2013)  # opcode OP_MSG
    return header + payload


MONGO_ERROR = _build_mongo_error()

# SMB2 minimal header-only response (64 bytes after NetBIOS framing)
SMB2_RESPONSE = (
    b"\x00\x00\x00\x40"            # NetBIOS session: length 64
    b"\xfeSMB"                     # SMB2 protocol id
    b"\x40\x00"                    # header structure size (always 64)
    b"\x00\x00"                    # credit charge
    b"\x00\x00\x00\x00"            # NT status: success
    b"\x00\x00"                    # command: negotiate
    b"\x01\x00"                    # credits granted
    b"\x00\x00\x00\x00"            # flags
    b"\x00\x00\x00\x00"            # next command offset
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # message ID (8 bytes)
    b"\x00\x00\x00\x00"            # process ID (4 bytes)
    b"\x00\x00\x00\x00"            # tree ID (4 bytes)
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # session ID (8 bytes)
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # signature (16 bytes)
)

# RDP X.224 connection confirm PDU (19 bytes total, verified)
RDP_CONFIRM = (
    b"\x03\x00\x00\x13"            # TPKT: version 3, length 19
    b"\x0e"                         # X.224 LI: 14 bytes follow
    b"\xd0"                         # X.224 code: connection confirm
    b"\x00\x00"                    # destination reference
    b"\x12\x34"                    # source reference
    b"\x00"                         # class and options
    b"\x02"                         # RDP negotiation response type
    b"\x00"                         # flags
    b"\x08\x00"                    # response length 8
    b"\x00\x00\x00\x00"            # selected protocol: classic RDP
)

SMTP_BANNER = b"220 mail.example.com ESMTP Postfix\r\n"
SMTP_EHLO_RESP = b"250-mail.example.com\r\n250 OK\r\n"
SMTP_AUTH_FAIL = b"535 5.7.8 Authentication failed\r\n"

POP3_BANNER = b"+OK POP3 server ready\r\n"
POP3_USER_OK = b"+OK\r\n"
POP3_PASS_FAIL = b"-ERR Authentication failed\r\n"

VNC_VERSION = b"RFB 003.008\n"
VNC_SEC_TYPES = b"\x01\x02"        # 1 type available: type 2 (VNC Authentication)
VNC_CHALLENGE = b"\x00" * 16       # 16-byte challenge for VNC auth
VNC_AUTH_FAILED = b"\x00\x00\x00\x01"  # auth result: failed

MEMCACHED_STATS = (
    b"STAT pid 1\r\n"
    b"STAT uptime 3600\r\n"
    b"STAT version 1.6.12\r\n"
    b"END\r\n"
)
MEMCACHED_ERROR = b"ERROR\r\n"


async def handle_ssh(reader, writer, logger, detector, config):
    """Emulate SSH service on the configured port.

    Sends a realistic SSH banner, captures the
    client payload, runs detection, and logs the
    connection. Always closes the connection cleanly.
    """
    src_ip, src_port = writer.get_extra_info("peername")
    dst_port = config.services["ssh"].port
    try:
        writer.write(SSH_BANNER)
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            data = b""
        detection = await detector.analyze(src_ip, dst_port, data, "ssh")
        await logger.log_connection({
            "timestamp": _now(), "src_ip": src_ip, "src_port": src_port,
            "dst_port": dst_port, "service": "ssh",
            "payload": _hex(data), "scanner_type": detection.get("scanner_type"),
        })
    except Exception as exc:
        if not _is_reset(exc):
            print(f"ssh handler error from {src_ip}: {exc}")
    finally:
        writer.close()


async def handle_ftp(reader, writer, logger, detector, config):
    """Emulate FTP service on the configured port.

    Sends a realistic FTP banner, captures the
    client payload, runs detection, and logs the
    connection. Always closes the connection cleanly.
    """
    src_ip, src_port = writer.get_extra_info("peername")
    dst_port = config.services["ftp"].port
    username = None
    password = None
    first_line = b""
    try:
        writer.write(FTP_BANNER)
        await writer.drain()
        try:
            first_line = await asyncio.wait_for(reader.readline(), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            first_line = b""
        if first_line.strip().upper().startswith(b"USER"):
            username = first_line.strip()[5:].decode(errors="replace").strip()
            writer.write(FTP_PASS_PROMPT)
            await writer.drain()
            try:
                pass_line = await asyncio.wait_for(reader.readline(), timeout=HANDLER_TIMEOUT)
            except asyncio.TimeoutError:
                pass_line = b""
            if pass_line.strip().upper().startswith(b"PASS"):
                password = pass_line.strip()[5:].decode(errors="replace").strip()
        writer.write(FTP_FAIL)
        await writer.drain()
        detection = await detector.analyze(src_ip, dst_port, first_line, "ftp")
        await logger.log_connection({
            "timestamp": _now(), "src_ip": src_ip, "src_port": src_port,
            "dst_port": dst_port, "service": "ftp",
            "payload": _hex(first_line),
            "credentials": f"{username}:{password}" if username else None,
            "scanner_type": detection.get("scanner_type"),
        })
    except Exception as exc:
        if not _is_reset(exc):
            print(f"ftp handler error from {src_ip}: {exc}")
    finally:
        writer.close()


async def handle_telnet(reader, writer, logger, detector, config):
    """Emulate Telnet service on the configured port.

    Sends a realistic Telnet banner, captures the
    client payload, runs detection, and logs the
    connection. Always closes the connection cleanly.
    """
    src_ip, src_port = writer.get_extra_info("peername")
    dst_port = config.services["telnet"].port
    username = None
    password = None
    first_data = b""
    try:
        writer.write(TELNET_NEGOTIATION + TELNET_BANNER)
        await writer.drain()
        try:
            first_data = await asyncio.wait_for(reader.readline(), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            first_data = b""
        username = first_data.strip().decode(errors="replace")
        writer.write(TELNET_PASS_PROMPT)
        await writer.drain()
        try:
            pass_data = await asyncio.wait_for(reader.readline(), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            pass_data = b""
        password = pass_data.strip().decode(errors="replace")
        writer.write(TELNET_FAIL)
        await writer.drain()
        detection = await detector.analyze(src_ip, dst_port, first_data, "telnet")
        await logger.log_connection({
            "timestamp": _now(), "src_ip": src_ip, "src_port": src_port,
            "dst_port": dst_port, "service": "telnet",
            "payload": _hex(first_data),
            "credentials": f"{username}:{password}" if username else None,
            "scanner_type": detection.get("scanner_type"),
        })
    except Exception as exc:
        if not _is_reset(exc):
            print(f"telnet handler error from {src_ip}: {exc}")
    finally:
        writer.close()


async def handle_http(reader, writer, logger, detector, config):
    """Emulate HTTP service on the configured port.

    Sends a realistic HTTP banner, captures the
    client payload, runs detection, and logs the
    connection. Always closes the connection cleanly.
    """
    src_ip, src_port = writer.get_extra_info("peername")
    dst_port = config.services["http"].port
    try:
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            data = b""
        writer.write(HTTP_RESPONSE)
        await writer.drain()
        detection = await detector.analyze(src_ip, dst_port, data, "http")
        await logger.log_connection({
            "timestamp": _now(), "src_ip": src_ip, "src_port": src_port,
            "dst_port": dst_port, "service": "http",
            "payload": _hex(data), "scanner_type": detection.get("scanner_type"),
        })
    except Exception as exc:
        if not _is_reset(exc):
            print(f"http handler error from {src_ip}: {exc}")
    finally:
        writer.close()


async def handle_https(reader, writer, logger, detector, config):
    """Emulate HTTPS service on the configured port.

    Sends a realistic HTTPS banner, captures the
    client payload, runs detection, and logs the
    connection. Always closes the connection cleanly.
    """
    src_ip, src_port = writer.get_extra_info("peername")
    dst_port = config.services["https"].port
    try:
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            data = b""
        writer.write(HTTP_RESPONSE)
        await writer.drain()
        detection = await detector.analyze(src_ip, dst_port, data, "https")
        await logger.log_connection({
            "timestamp": _now(), "src_ip": src_ip, "src_port": src_port,
            "dst_port": dst_port, "service": "https",
            "payload": _hex(data), "scanner_type": detection.get("scanner_type"),
        })
    except Exception as exc:
        if not _is_reset(exc):
            print(f"https handler error from {src_ip}: {exc}")
    finally:
        writer.close()


async def handle_mysql(reader, writer, logger, detector, config):
    """Emulate MySQL service on the configured port.

    Sends a realistic MySQL banner, captures the
    client payload, runs detection, and logs the
    connection. Always closes the connection cleanly.
    """
    src_ip, src_port = writer.get_extra_info("peername")
    dst_port = config.services["mysql"].port
    try:
        writer.write(MYSQL_HANDSHAKE)
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            data = b""
        writer.write(MYSQL_AUTH_ERROR)
        await writer.drain()
        detection = await detector.analyze(src_ip, dst_port, data, "mysql")
        await logger.log_connection({
            "timestamp": _now(), "src_ip": src_ip, "src_port": src_port,
            "dst_port": dst_port, "service": "mysql",
            "payload": _hex(data), "scanner_type": detection.get("scanner_type"),
        })
    except Exception as exc:
        if not _is_reset(exc):
            print(f"mysql handler error from {src_ip}: {exc}")
    finally:
        writer.close()


async def handle_postgresql(reader, writer, logger, detector, config):
    """Emulate PostgreSQL service on the configured port.

    Sends a realistic PostgreSQL banner, captures the
    client payload, runs detection, and logs the
    connection. Always closes the connection cleanly.
    """
    src_ip, src_port = writer.get_extra_info("peername")
    dst_port = config.services["postgresql"].port
    try:
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            data = b""
        writer.write(PG_AUTH_REQUEST)
        await writer.drain()
        # Read the client password response before closing with an error
        try:
            await asyncio.wait_for(reader.read(4096), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            pass
        writer.write(PG_AUTH_ERROR)
        await writer.drain()
        detection = await detector.analyze(src_ip, dst_port, data, "postgresql")
        await logger.log_connection({
            "timestamp": _now(), "src_ip": src_ip, "src_port": src_port,
            "dst_port": dst_port, "service": "postgresql",
            "payload": _hex(data), "scanner_type": detection.get("scanner_type"),
        })
    except Exception as exc:
        if not _is_reset(exc):
            print(f"postgresql handler error from {src_ip}: {exc}")
    finally:
        writer.close()


async def handle_redis(reader, writer, logger, detector, config):
    """Emulate Redis service on the configured port.

    Sends a realistic Redis banner, captures the
    client payload, runs detection, and logs the
    connection. Always closes the connection cleanly.
    """
    src_ip, src_port = writer.get_extra_info("peername")
    dst_port = config.services["redis"].port
    try:
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            data = b""
        # RESP protocol commands start with * (array); anything else gets PONG
        if data.startswith(b"*"):
            writer.write(b"-NOAUTH Authentication required.\r\n")
        else:
            writer.write(b"+PONG\r\n")
        await writer.drain()
        detection = await detector.analyze(src_ip, dst_port, data, "redis")
        await logger.log_connection({
            "timestamp": _now(), "src_ip": src_ip, "src_port": src_port,
            "dst_port": dst_port, "service": "redis",
            "payload": _hex(data), "scanner_type": detection.get("scanner_type"),
        })
    except Exception as exc:
        if not _is_reset(exc):
            print(f"redis handler error from {src_ip}: {exc}")
    finally:
        writer.close()


async def handle_mongodb(reader, writer, logger, detector, config):
    """Emulate MongoDB service on the configured port.

    Sends a realistic MongoDB banner, captures the
    client payload, runs detection, and logs the
    connection. Always closes the connection cleanly.
    """
    src_ip, src_port = writer.get_extra_info("peername")
    dst_port = config.services["mongodb"].port
    try:
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            data = b""
        writer.write(MONGO_ERROR)
        await writer.drain()
        detection = await detector.analyze(src_ip, dst_port, data, "mongodb")
        await logger.log_connection({
            "timestamp": _now(), "src_ip": src_ip, "src_port": src_port,
            "dst_port": dst_port, "service": "mongodb",
            "payload": _hex(data), "scanner_type": detection.get("scanner_type"),
        })
    except Exception as exc:
        if not _is_reset(exc):
            print(f"mongodb handler error from {src_ip}: {exc}")
    finally:
        writer.close()


async def handle_smb(reader, writer, logger, detector, config):
    """Emulate SMB service on the configured port.

    Sends a realistic SMB banner, captures the
    client payload, runs detection, and logs the
    connection. Always closes the connection cleanly.
    """
    src_ip, src_port = writer.get_extra_info("peername")
    dst_port = config.services["smb"].port
    try:
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            data = b""
        writer.write(SMB2_RESPONSE)
        await writer.drain()
        detection = await detector.analyze(src_ip, dst_port, data, "smb")
        await logger.log_connection({
            "timestamp": _now(), "src_ip": src_ip, "src_port": src_port,
            "dst_port": dst_port, "service": "smb",
            "payload": _hex(data), "scanner_type": detection.get("scanner_type"),
        })
    except Exception as exc:
        if not _is_reset(exc):
            print(f"smb handler error from {src_ip}: {exc}")
    finally:
        writer.close()


async def handle_rdp(reader, writer, logger, detector, config):
    """Emulate RDP service on the configured port.

    Sends a realistic RDP banner, captures the
    client payload, runs detection, and logs the
    connection. Always closes the connection cleanly.
    """
    src_ip, src_port = writer.get_extra_info("peername")
    dst_port = config.services["rdp"].port
    try:
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            data = b""
        writer.write(RDP_CONFIRM)
        await writer.drain()
        detection = await detector.analyze(src_ip, dst_port, data, "rdp")
        await logger.log_connection({
            "timestamp": _now(), "src_ip": src_ip, "src_port": src_port,
            "dst_port": dst_port, "service": "rdp",
            "payload": _hex(data), "scanner_type": detection.get("scanner_type"),
        })
    except Exception as exc:
        if not _is_reset(exc):
            print(f"rdp handler error from {src_ip}: {exc}")
    finally:
        writer.close()


async def handle_smtp(reader, writer, logger, detector, config):
    """Emulate SMTP service on the configured port.

    Sends a realistic SMTP banner, captures the
    client payload, runs detection, and logs the
    connection. Always closes the connection cleanly.
    """
    src_ip, src_port = writer.get_extra_info("peername")
    dst_port = config.services["smtp"].port
    username = None
    password = None
    first_line = b""
    try:
        writer.write(SMTP_BANNER)
        await writer.drain()
        try:
            first_line = await asyncio.wait_for(reader.readline(), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            first_line = b""
        if first_line.strip().upper().startswith(b"EHLO"):
            writer.write(SMTP_EHLO_RESP)
            await writer.drain()
            try:
                auth_line = await asyncio.wait_for(reader.readline(), timeout=HANDLER_TIMEOUT)
            except asyncio.TimeoutError:
                auth_line = b""
            # AUTH LOGIN sends credentials as two separate base64-encoded lines,
            # each preceded by a 334 server prompt to solicit the next value
            if auth_line.strip().upper().startswith(b"AUTH"):
                writer.write(b"334 Username:\r\n")
                await writer.drain()
                try:
                    cred1 = await asyncio.wait_for(reader.readline(), timeout=HANDLER_TIMEOUT)
                except asyncio.TimeoutError:
                    cred1 = b""
                writer.write(b"334 Password:\r\n")
                await writer.drain()
                try:
                    cred2 = await asyncio.wait_for(reader.readline(), timeout=HANDLER_TIMEOUT)
                except asyncio.TimeoutError:
                    cred2 = b""
                username = cred1.strip().decode(errors="replace")
                password = cred2.strip().decode(errors="replace")
        writer.write(SMTP_AUTH_FAIL)
        await writer.drain()
        detection = await detector.analyze(src_ip, dst_port, first_line, "smtp")
        await logger.log_connection({
            "timestamp": _now(), "src_ip": src_ip, "src_port": src_port,
            "dst_port": dst_port, "service": "smtp",
            "payload": _hex(first_line),
            "credentials": f"{username}:{password}" if username else None,
            "scanner_type": detection.get("scanner_type"),
        })
    except Exception as exc:
        if not _is_reset(exc):
            print(f"smtp handler error from {src_ip}: {exc}")
    finally:
        writer.close()


async def handle_pop3(reader, writer, logger, detector, config):
    """Emulate POP3 service on the configured port.

    Sends a realistic POP3 banner, captures the
    client payload, runs detection, and logs the
    connection. Always closes the connection cleanly.
    """
    src_ip, src_port = writer.get_extra_info("peername")
    dst_port = config.services["pop3"].port
    username = None
    password = None
    first_line = b""
    try:
        writer.write(POP3_BANNER)
        await writer.drain()
        try:
            first_line = await asyncio.wait_for(reader.readline(), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            first_line = b""
        if first_line.strip().upper().startswith(b"USER"):
            username = first_line.strip()[5:].decode(errors="replace").strip()
            writer.write(POP3_USER_OK)
            await writer.drain()
            try:
                pass_line = await asyncio.wait_for(reader.readline(), timeout=HANDLER_TIMEOUT)
            except asyncio.TimeoutError:
                pass_line = b""
            if pass_line.strip().upper().startswith(b"PASS"):
                password = pass_line.strip()[5:].decode(errors="replace").strip()
        writer.write(POP3_PASS_FAIL)
        await writer.drain()
        detection = await detector.analyze(src_ip, dst_port, first_line, "pop3")
        await logger.log_connection({
            "timestamp": _now(), "src_ip": src_ip, "src_port": src_port,
            "dst_port": dst_port, "service": "pop3",
            "payload": _hex(first_line),
            "credentials": f"{username}:{password}" if username else None,
            "scanner_type": detection.get("scanner_type"),
        })
    except Exception as exc:
        if not _is_reset(exc):
            print(f"pop3 handler error from {src_ip}: {exc}")
    finally:
        writer.close()


async def handle_vnc(reader, writer, logger, detector, config):
    """Emulate VNC service on the configured port.

    Sends a realistic VNC banner, captures the
    client payload, runs detection, and logs the
    connection. Always closes the connection cleanly.
    """
    src_ip, src_port = writer.get_extra_info("peername")
    dst_port = config.services["vnc"].port
    try:
        writer.write(VNC_VERSION)
        await writer.drain()
        try:
            client_version = await asyncio.wait_for(reader.read(12), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            client_version = b""
        writer.write(VNC_SEC_TYPES)
        await writer.drain()
        # Read the 1-byte security type selection from the client
        try:
            await asyncio.wait_for(reader.read(1), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            pass
        writer.write(VNC_CHALLENGE)
        await writer.drain()
        # Read the 16-byte DES-encrypted auth response
        try:
            auth_response = await asyncio.wait_for(reader.read(16), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            auth_response = b""
        writer.write(VNC_AUTH_FAILED)
        await writer.drain()
        payload = client_version + auth_response
        detection = await detector.analyze(src_ip, dst_port, payload, "vnc")
        await logger.log_connection({
            "timestamp": _now(), "src_ip": src_ip, "src_port": src_port,
            "dst_port": dst_port, "service": "vnc",
            "payload": _hex(payload), "scanner_type": detection.get("scanner_type"),
        })
    except Exception as exc:
        if not _is_reset(exc):
            print(f"vnc handler error from {src_ip}: {exc}")
    finally:
        writer.close()


async def handle_memcached(reader, writer, logger, detector, config):
    """Emulate Memcached service on the configured port.

    Sends a realistic Memcached banner, captures the
    client payload, runs detection, and logs the
    connection. Always closes the connection cleanly.
    """
    src_ip, src_port = writer.get_extra_info("peername")
    dst_port = config.services["memcached"].port
    try:
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            data = b""
        if data.strip().lower().startswith(b"stats"):
            writer.write(MEMCACHED_STATS)
        else:
            writer.write(MEMCACHED_ERROR)
        await writer.drain()
        detection = await detector.analyze(src_ip, dst_port, data, "memcached")
        await logger.log_connection({
            "timestamp": _now(), "src_ip": src_ip, "src_port": src_port,
            "dst_port": dst_port, "service": "memcached",
            "payload": _hex(data), "scanner_type": detection.get("scanner_type"),
        })
    except Exception as exc:
        if not _is_reset(exc):
            print(f"memcached handler error from {src_ip}: {exc}")
    finally:
        writer.close()
