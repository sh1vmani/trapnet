# MongoDB Protocol

MongoDB runs on TCP port 27017. It is a document-oriented database that stores data as BSON (Binary JSON). In its early versions MongoDB defaulted to no authentication, which led to widespread exposure and data theft. The "MongoDB apocalypse" in 2017 involved attackers deleting databases from hundreds of thousands of exposed instances and demanding ransom.

## How MongoDB wire protocol works

MongoDB uses a binary wire protocol. Every message has a fixed 16-byte header followed by a variable payload.

The header fields:

```
messageLength  int32   total message size including header
requestID      int32   client-assigned request ID
responseTo     int32   requestID of the message this responds to (0 for requests)
opCode         int32   operation type
```

Modern MongoDB (version 3.6+) uses `OP_MSG` (opcode `2013`) for most communication. `OP_MSG` carries BSON documents in typed sections. Section kind `0` is a body document; kind `1` is a document sequence.

## What trapnet sends

trapnet reads the incoming packet and responds with a BSON error document in an `OP_MSG` frame. The response is built dynamically in `_build_mongo_error()`:

```python
def _build_mongo_error() -> bytes:
    ok_field    = b"\x10ok\x00" + struct.pack("<i", 0)
    errmsg_val  = b"Unauthorized\x00"
    errmsg_field = b"\x02errmsg\x00" + struct.pack("<I", len(errmsg_val)) + errmsg_val
    doc_body    = ok_field + errmsg_field + b"\x00"
    doc         = struct.pack("<i", len(doc_body) + 4) + doc_body
    section     = b"\x00" + doc          # section kind 0 (body)
    flags       = struct.pack("<I", 0)
    payload     = flags + section
    header      = struct.pack("<iiii", 16 + len(payload), 0, 0, 2013)
    return header + payload
```

The resulting BSON document is `{ok: 0, errmsg: "Unauthorized"}`. This is the exact structure a real MongoDB server returns when authentication is required but not provided.

## BSON encoding

BSON (Binary JSON) encodes documents as a length-prefixed list of typed key-value pairs:

- `\x10` = int32
- `\x02` = string (UTF-8, length-prefixed, null-terminated)
- `\x00` = document terminator

A document starts with its total byte length (int32, little-endian), contains fields, and ends with `\x00`. Strings within documents are encoded as int32 length + UTF-8 bytes + `\x00`.

## The "MongoDB apocalypse"

In January 2017, security researchers documented over 27,000 MongoDB databases that had been wiped and replaced with ransom notes. The databases were publicly accessible with no authentication. Automated bots scanned port 27017, connected without credentials, dropped all databases, and created a new database containing only a ransom demand. The attackers used the MongoDB wire protocol directly, no special tools required.

## Common attacker behaviors

**Unauthenticated access probe.** Scanners send a `listDatabases` or `isMaster` command immediately on connection. If authentication is not required, the response includes database names and sizes, which is enough to assess the value of the target.

**Data exfiltration and wipe.** After confirming access, automated tools dump all collections and then drop the databases, leaving a ransom note.

**Command injection via operators.** Web applications that pass user input directly to MongoDB queries are vulnerable to NoSQL injection using operators like `$where`, `$regex`, and `$gt`.

## Further reading

- [MySQL handshake](mysql-handshake.md)
- [Services explained](../03-code-walkthrough/services-explained.md)
- [Network isolation best practices](../06-security-concepts/network-isolation-best-practices.md)
