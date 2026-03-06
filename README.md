# authblndr

Scans a list of hosts/endpoints for broken authentication — specifically, services that return 401/403 or redirect to a login page, but then accept *any* `Authorization` header value and serve a 2xx response.

## How it works

1. For each host, send a plain GET request (redirects not followed).
2. If the response is `401`, `403`, or a `3xx` redirect, retry with `Authorization: foo`.
3. If the retry returns `2xx` — it's **vulnerable**. The service checks for the presence of an auth header, not its validity.

## Install

```sh
go install github.com/cybercdh/authblndr@latest
```

Or build from source:

```sh
git clone https://github.com/cybercdh/authblndr
cd authblndr
go build -o authblndr .
```

## Usage

```sh
cat subdomains.txt | authblndr [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-c` | `20` | Concurrent workers |
| `-t` | `10s` | HTTP request timeout |
| `-v` | `false` | Verbose — show all results, not just vulnerable hosts |

### Examples

```sh
# Basic scan
cat subdomains.txt | authblndr

# Faster, with verbose output
cat subdomains.txt | authblndr -c 50 -t 5s -v

# Single target
echo "example.com/api/v1" | authblndr
```

### Input format

One host or URL per line. Lines starting with `#` are ignored. Bare hostnames get `https://` prepended; HTTP fallback is attempted automatically if HTTPS fails.

```
# internal services
api.example.com
dev.example.com/admin
http://legacy.example.com
```

### Output

```
  VULN  https://api.example.com  base=401 auth=200
  SAFE  https://dev.example.com  base=403 auth=403
  OK    https://pub.example.com  status=200

Scanned 3 hosts — 1 vulnerable
```

## License

MIT
