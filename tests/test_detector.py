import time
import pytest
from trapnet.core.detector import AttackDetector


@pytest.mark.asyncio
async def test_metasploit_smb():
    d = AttackDetector()
    result = await d.analyze(
        "1.2.3.4", 445, b"\x00\x00\x00\x2f\xff\x53\x4d\x42extra", "smb"
    )
    assert result["scanner_type"] == "METASPLOIT"
    assert result["confidence"] == 0.9


@pytest.mark.asyncio
async def test_nmap_probe():
    d = AttackDetector()
    result = await d.analyze("1.2.3.4", 80, b"GET / HTTP/1.0\r\n", "http")
    assert result["scanner_type"] == "NMAP"
    assert result["confidence"] == 0.8


@pytest.mark.asyncio
async def test_clean_connection():
    d = AttackDetector()
    result = await d.analyze("1.2.3.4", 22, b"", "ssh")
    assert "scanner_type" in result
    assert "confidence" in result
    assert result["scanner_type"] in ("NMAP", None)


@pytest.mark.asyncio
async def test_credential_stuffer():
    d = AttackDetector()
    # Non-Nmap, non-empty payload so CREDENTIAL_STUFFER wins over NMAP (0.75 vs 0.8)
    for _ in range(4):
        result = await d.analyze("1.2.3.4", 22, b"ssh-rsa AAAA", "ssh")
    assert result["scanner_type"] == "CREDENTIAL_STUFFER"


@pytest.mark.asyncio
async def test_tracker_cleanup():
    d = AttackDetector()
    old_ts = time.monotonic() - 400   # older than _TRACKER_TTL (300 s)
    fresh_ts = time.monotonic() - 10
    d._tracker["1.2.3.4"] = [(old_ts, 22, "ssh")]
    d._tracker["5.6.7.8"] = [(fresh_ts, 80, "http")]
    await d._clean_tracker()
    assert "1.2.3.4" not in d._tracker
    assert "5.6.7.8" in d._tracker
