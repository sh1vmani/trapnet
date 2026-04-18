from __future__ import annotations
import asyncio
import time


class AttackDetector:

    def __init__(self) -> None:
        # Maps each source IP to a list of (timestamp, port, service) tuples
        self._tracker: dict[str, list[tuple[float, int, str]]] = {}
        # Lock is created lazily to avoid instantiating asyncio primitives
        # before a running event loop exists (same reason as geoip.py)
        self._lock: asyncio.Lock | None = None

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def _clean_tracker(self) -> None:
        # Remove events older than 5 minutes to bound memory usage
        cutoff = time.monotonic() - 300
        async with self._get_lock():
            for ip in list(self._tracker):
                self._tracker[ip] = [e for e in self._tracker[ip] if e[0] > cutoff]
                if not self._tracker[ip]:
                    del self._tracker[ip]

    async def analyze(
        self,
        src_ip: str,
        dst_port: int,
        payload: bytes,
        service: str,
    ) -> dict:
        # Clean stale entries before evaluating this connection
        await self._clean_tracker()

        now = time.monotonic()
        payload = payload or b""
        payload_lower = payload.lower()

        # Record this event and take a snapshot, both under the lock.
        # Detection logic runs outside the lock so it never blocks other coroutines.
        async with self._get_lock():
            if src_ip not in self._tracker:
                self._tracker[src_ip] = []
            self._tracker[src_ip].append((now, dst_port, service))
            events = list(self._tracker[src_ip])

        events_last_60s = [e for e in events if now - e[0] <= 60]
        events_last_30s = [e for e in events if now - e[0] <= 30]
        events_last_10s = [e for e in events if now - e[0] <= 10]
        unique_ports_60s = len(set(e[1] for e in events_last_60s))

        candidates: dict[str, tuple[float, list[str]]] = {}

        # Metasploit: highest confidence, most specific payload signatures
        msf: list[str] = []
        if b"msfconsole" in payload_lower or b"metasploit" in payload_lower:
            msf.append("metasploit string in payload")
        if service == "smb" and payload.startswith(b"\x00\x00\x00\x2f\xff\x53\x4d\x42"):
            msf.append("EternalBlue SMB probe signature")
        if service == "rdp" and len(payload) >= 6 and payload[5:6] == b"\xe0":
            msf.append("MS17-010 RDP probe pattern")
        if msf:
            candidates["METASPLOIT"] = (0.9, msf)

        # Masscan: extremely high connection rate, typically with empty payloads
        masscan: list[str] = []
        if len(events_last_10s) > 20:
            masscan.append(f"{len(events_last_10s)} connections from same IP in 10 seconds")
        if len(payload) == 0 and len(events_last_10s) > 5:
            masscan.append("zero byte payload at high connection rate")
        if masscan:
            candidates["MASSCAN"] = (0.85, masscan)

        # Nmap: known probe strings, multi-port sweep (>7), or empty TCP probe.
        # Threshold is >7 to create clear separation from Generic scanner (>3).
        nmap_probe_strings = [
            b"GET / HTTP/1.0",
            b"OPTIONS * HTTP/1.0",
            b"HELP\r\n",
            b"QUIT\r\n",
        ]
        nmap: list[str] = []
        for probe in nmap_probe_strings:
            if probe in payload:
                nmap.append(f"Nmap probe string: {probe!r}")
        if unique_ports_60s > 7:
            nmap.append(f"{unique_ports_60s} unique ports hit in 60 seconds")
        if len(payload) == 0 and service not in ("udp",):
            nmap.append("zero byte payload on TCP service")
        if nmap:
            candidates["NMAP"] = (0.8, nmap)

        # Shodan/Censys: crawler identifiers or banner-grab-and-drop, web ports only.
        # Zero-byte connections on non-web ports have other explanations and are not
        # reliably attributable to Shodan.
        shodan: list[str] = []
        if service in ("http", "https"):
            for ua in (b"shodan", b"censys", b"zgrab", b"masscan"):
                if ua in payload_lower:
                    shodan.append(f"known crawler identifier in request: {ua.decode()}")
            if len(payload) == 0:
                shodan.append("banner grab with no request body on web port")
        if shodan:
            candidates["SHODAN"] = (0.7, shodan)

        # Credential stuffer: rapid auth attempts or common passwords in payload
        auth_services = {"ssh", "ftp", "telnet", "pop3", "smtp"}
        common_passwords = [
            b"admin", b"password", b"123456", b"root",
            b"test", b"guest", b"12345678",
        ]
        cred: list[str] = []
        if service in auth_services:
            auth_events_30s = [e for e in events_last_30s if e[2] == service]
            if len(auth_events_30s) > 3:
                cred.append(f"{len(auth_events_30s)} login attempts on {service} in 30 seconds")
            for pw in common_passwords:
                # Substring match catches passwords embedded in larger credential strings
                if pw in payload_lower:
                    cred.append(f"common password string in payload: {pw.decode()!r}")
                    break
        if cred:
            candidates["CREDENTIAL_STUFFER"] = (0.75, cred)

        # Generic scanner: multiple ports touched with no stronger signal above
        generic: list[str] = []
        if unique_ports_60s > 3:
            generic.append(f"{unique_ports_60s} unique ports hit in 60 seconds")
        if generic:
            candidates["GENERIC_SCANNER"] = (0.5, generic)

        if not candidates:
            return {"scanner_type": None, "confidence": 0.0, "indicators": []}

        # Return the highest-confidence match when multiple categories trigger
        best = max(candidates, key=lambda k: candidates[k][0])
        confidence, indicators = candidates[best]
        return {"scanner_type": best, "confidence": confidence, "indicators": indicators}
