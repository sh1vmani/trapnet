# logger.py Explained

`trapnet/core/logger.py` writes connection records to two sinks simultaneously: a SQLite database and a newline-delimited JSON file.

## Two sinks

**SQLite** is the primary store. The dashboard queries it. It supports structured queries (filter by IP, service, date range), aggregations (top IPs, hourly counts), and efficient indexed reads.

**JSON lines** is a secondary export format. Each line is a complete JSON object. This format is importable directly into log analysis tools (Splunk, Elastic, jq, pandas) without needing a database client.

Both sinks receive every record. If the JSON write fails (e.g., disk full), the SQLite write still succeeds -- writes are independent.

## Schema

```sql
CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    service TEXT,
    payload TEXT,
    credentials TEXT,
    scanner_type TEXT,
    country TEXT,
    city TEXT,
    raw_data BLOB
)
```

`payload` stores the hex-encoded bytes the attacker sent. `credentials` stores a JSON-serialized object like `{"username": "root", "password": "admin"}` when the protocol exposes credentials. `raw_data` is reserved for future use.

## Parameterized queries

The SQL insert uses positional `?` placeholders, never string interpolation:

```python
sql = "INSERT INTO connections (...) VALUES (?, ?, ?, ...)"
await db.execute(sql, row)
```

This is critical because `payload` and `credentials` contain attacker-controlled strings. Interpolating them directly into SQL would allow SQL injection into the honeypot's own log database.

## Async I/O

Both writes use async libraries (`aiosqlite`, `aiofiles`) so they yield control to the event loop while waiting for disk I/O. Neither write blocks the honeypot from handling other connections.

The two writes happen concurrently inside `log_connection()` via `asyncio.gather()`.

## init_db

`init_db(db_path)` creates the `logs/` directory and runs the `CREATE TABLE IF NOT EXISTS` statement. It is called once at startup. Subsequent runs on an existing database are idempotent.

## Statistics queries

`get_stats(db_path)` runs five queries to produce the data the dashboard displays:

- total connection count
- top 5 services by hit count
- top 5 source IPs by hit count
- hourly connection counts for the last 24 hours (for the dashboard chart)
- scanner type breakdown

All queries run sequentially inside a single `aiosqlite` connection context.

## Export functions

`export_json(db_path, path)` and `export_csv(db_path, path)` write full database exports to files. They cap reads at 10 million rows to bound memory usage. For very large databases, a streaming approach would be more appropriate -- but 10 million honeypot connections represents months of high-volume capture.

## Further reading

- [Data flow walkthrough](../02-architecture/data-flow-walkthrough.md)
- [Logging and forensics](../06-security-concepts/logging-and-forensics.md)
