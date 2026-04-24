# Redis Protocol

Redis runs on TCP port 6379. It is an in-memory data store used as a cache, message broker, and session store. Redis was famously configured without authentication by default in early versions, and many exposed instances were exploited to write SSH keys, cron jobs, or webshells to disk by abusing Redis's ability to write its database file to arbitrary paths.

## How Redis communication works

Redis uses RESP (REdis Serialization Protocol). It is a simple text-based protocol where commands are sent as arrays and responses use type-prefixed lines.

A command array looks like:

```
*3\r\n
$3\r\n
SET\r\n
$3\r\n
key\r\n
$5\r\n
value\r\n
```

The `*3` means an array of 3 elements. Each `$N` prefix introduces a bulk string of N bytes. Responses use `+` for simple strings, `-` for errors, `:` for integers, `$` for bulk strings, and `*` for arrays.

The `PING` command is the simplest probe: the client sends `PING` and a healthy unauthenticated server responds `+PONG\r\n`.

## What trapnet does

trapnet reads up to 1024 bytes and branches on the first byte:

```python
if data.startswith(b"*"):
    writer.write(b"-NOAUTH Authentication required.\r\n")
else:
    writer.write(b"+PONG\r\n")
```

RESP array commands start with `*`. A `PING` command arrives as `*1\r\n$4\r\nPING\r\n`, which starts with `*`. A raw plaintext `PING\r\n` does not start with `*` and gets a `+PONG` response. This simulates a server that is partially configured, which is exactly the state many exposed Redis instances are in.

The `NOAUTH` error is the exact response a real Redis server with authentication enabled sends to any command before `AUTH`.

## The classic Redis attack pattern

The attack that made Redis infamous:

1. Connect to port 6379 with no authentication required.
2. Use `CONFIG SET dir /root/.ssh` to point the database file directory at the SSH authorized_keys folder.
3. Use `CONFIG SET dbfilename authorized_keys` to set the filename.
4. Use `SET` to store the attacker's SSH public key as a Redis value.
5. Use `BGSAVE` to write the Redis database (now containing the SSH key) to disk.
6. SSH in as root using the injected key.

trapnet logs any connection that attempts these commands, but does not execute them. The raw payload in the log will show exactly what the attacker tried to do.

## Common attacker behaviors

**Unauthenticated access probe.** Almost every Redis scanner begins with `PING` or `INFO` to confirm the server is responding and whether authentication is required.

**CONFIG GET/SET probes.** After confirming access, automated tools try `CONFIG GET dir` and `CONFIG GET dbfilename` to determine the write path.

**Cryptocurrency miner deployment.** Many automated Redis exploits write a cron job or SSH key and then immediately download and execute a miner.

## Further reading

- [Services explained](../03-code-walkthrough/services-explained.md)
- [Network isolation best practices](../06-security-concepts/network-isolation-best-practices.md)
- [How attackers scan networks](../01-concepts/how-attackers-scan-networks.md)
