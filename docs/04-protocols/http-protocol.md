# HTTP Protocol

HTTP runs on TCP port 80 (plain) and port 443 (TLS). Both are among the most scanned ports on the internet. Web servers are targeted by vulnerability scanners, content discovery tools, and crawlers from security indexing services like Shodan and Censys.

## How an HTTP request works

HTTP/1.1 uses a plain-text request/response model. The client sends a request line, headers, an empty line, and optionally a body:

```
GET / HTTP/1.1\r\n
Host: example.com\r\n
User-Agent: Mozilla/5.0\r\n
\r\n
```

The server responds with a status line, headers, an empty line, and the body:

```
HTTP/1.1 200 OK\r\n
Server: Apache/2.4.57 (Ubuntu)\r\n
Content-Type: text/html\r\n
\r\n
<!DOCTYPE html>...
```

The `User-Agent` header is the most common place scanner tools identify themselves. Shodan, Censys, zgrab, and Masscan all send recognizable user agents.

## What trapnet does

trapnet reads up to 4096 bytes from the connection (the HTTP request) and then replies with a fixed Apache default page:

```python
HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: Apache/2.4.57 (Ubuntu)\r\n"
    b"Content-Type: text/html\r\n"
    b"\r\n"
    b"<!DOCTYPE html><html><body>"
    b"<h1>Apache2 Ubuntu Default Page</h1>"
    b"</body></html>"
)
```

The same handler runs on both port 80 (http) and port 443 (https). On port 443, scanners that do a proper TLS handshake before sending HTTP will not get a valid TLS response, because trapnet does not implement TLS. However, many scanners attempt plain HTTP even on port 443 when checking for misconfigurations, and those do receive the response.

## Why the Apache default page

The Apache default page is what a freshly installed Ubuntu server shows before any web content is deployed. It is one of the most common responses on the internet. A scanner seeing this response will log the server as a potential Apache target and may proceed to attempt directory enumeration, CVE probing, or web application attacks.

## What the full request reveals

The raw HTTP request logged by trapnet contains significant intelligence:

- **User-Agent:** Identifies the scanning tool or browser.
- **Request path:** Reveals what the attacker is looking for. Paths like `/admin`, `/.env`, `/wp-login.php`, `/phpmyadmin` indicate specific targets.
- **Headers:** Custom headers can identify automated tools or reveal proxy infrastructure.
- **Request method:** `GET` is normal. `OPTIONS`, `PROPFIND`, `TRACE` indicate specific vulnerability probes.

## Further reading

- [How Shodan is detected](../05-detection/how-shodan-is-detected.md)
- [How Nmap is detected](../05-detection/how-nmap-is-detected.md)
- [Attack detection techniques](../01-concepts/attack-detection-techniques.md)
