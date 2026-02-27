# CODoH Integration in dnscrypt-proxy

## What

dnscrypt-proxy acts as the CODoH client, replacing `codoh-client`. Local DNS queries resolve transparently via the CODoH protocol — standard ODoH wrapped with an enclave-based cache layer.

## How It Works

```
dig query → dnscrypt-proxy:5380
  1. Encrypt Q_T (standard ODoH, encrypted to target's pk_T)
  2. Canonicalize query ("example.com.:1"), encrypt Q_E (HPKE to enclave pk_E), derive k_r via Export
  3. Pad both Q_E and Q_T to 256-byte buckets
  4. POST to proxy with Q_T as body + X-CoDOH-Query: base64(Q_E) header
  5. Parse response:
     - application/codoh-response → tagged chunks: try enclave chunk (cache hit), fall back to target chunk (miss)
     - application/codoh-cached → direct AES-GCM decrypt with k_r (CODoH-base mode)
     - application/oblivious-dns-message → degraded ODoH (enclave down)
  6. Return decrypted DNS response to client
```

Key rotation: `X-CoDOH-Key-Rotated: true` header triggers async pk_E refresh.
Fallback: if enclave key fetch fails, degrades to standard ODoH transparently.

## Files

| File | Role |
|---|---|
| `codoh.go` (new) | HPKE encrypt (circl), AES-GCM decrypt, pad/unpad, canonicalize, tagged-chunk parser, enclave key cache |
| `query_processing.go` | `processCODoHQuery()` — full CODoH flow; `processODoHQueryFallback()` — graceful degradation |
| `xtransport.go` | `CODoHQuery()` + `FetchWithExtraHeaders()` — HTTP transport with extra headers |
| `serversInfo.go` | CODoH fast-path in `_fetchODoHTargetInfo` (skips ODoH test query that hangs on codohproxy) |
| `config.go` | `CODoHGlobalConfig` struct, `[codoh]` TOML section |
| `proxy.go` | `codohConfig` field on Proxy |
| `config_loader.go` | Propagates config to proxy |

## TOML Config

```toml
[codoh]
enabled = true
server_names = ['my-odoh-target']   # which ODoH servers to upgrade to CODoH
proxy_host = 'codoh-proxy.example.com'  # proxy with /enclave-keys + /proxy endpoints
```

Servers listed in `server_names` must also be defined as ODoH targets (via stamps).

## How to Run (E2E Test)

### Prerequisites

- SGX-capable machine with EGo runtime
- `coredns-test` binary with `codohtarget` + `codohproxy` plugins (from `../coredns/`)
- TLS certs trusted by dnscrypt-proxy

### 1. Generate test certs

```bash
# CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /tmp/test-ca-key.pem -out /tmp/test-ca.pem -days 365 -nodes -subj "/CN=TestCA"

# Server cert signed by CA (localhost + 127.0.0.1)
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /tmp/test-server-key.pem -out /tmp/test-server.csr -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
openssl x509 -req -in /tmp/test-server.csr -CA /tmp/test-ca.pem -CAkey /tmp/test-ca-key.pem \
  -CAcreateserial -out /tmp/test-server.pem -days 365 -copy_extensions copyall

# Signing key for target → enclave provisioning
openssl genrsa -out /tmp/target-signing.pem 2048
```

### 2. Write Corefiles

**Corefile.target** (ODoH target on :8443):
```
.:25356 {
    codohtarget {
        port 8443
        tls_cert /tmp/test-server.pem
        tls_key /tmp/test-server-key.pem
        upstream 1.1.1.1:53
        signing_key /tmp/target-signing.pem
        enclave_url https://127.0.0.1:8444
        log_queries true
    }
    errors
    log
}
```

**Corefile.proxy** (CODoH proxy on :8080):
```
.:25357 {
    codohproxy {
        target https://127.0.0.1:8443/dns-query
        port 8080
        tls_cert /tmp/test-server.pem
        tls_key /tmp/test-server-key.pem
        insecure_skip_verify true
        enclave_enabled
        enclave_socket /tmp/codoh-enclave.sock
        enclave_bypass_on_failure true
    }
    errors
    log
}
```

### 3. Start infrastructure (order matters)

```bash
# Enclave (SGX) — must start first, serves attestation on :8444
cd ../coredns/enclave
ego run enclave --socket /tmp/codoh-enclave.sock &
sleep 8  # wait for SGX quote generation + attestation server

# Target — provisions signing key to enclave on startup
cd ../coredns
CODOH_COVER_COUNT=0 ./coredns-test -conf Corefile.target &
sleep 4

# Proxy — connects to enclave socket, caches pk_E
./coredns-test -conf Corefile.proxy &
sleep 2
```

### 4. Build and run dnscrypt-proxy

```bash
cd dnscrypt-proxy/dnscrypt-proxy
go build -o /tmp/codoh-test/dnscrypt-proxy .
cd /tmp/codoh-test
./dnscrypt-proxy -config dnscrypt-proxy.toml &
```

### 5. Test

```bash
dig @127.0.0.1 -p 5380 example.com A +short
# Expected: 104.18.26.120 / 104.18.27.120
```

### Example dnscrypt-proxy.toml

```toml
listen_addresses = ['127.0.0.1:5380']
timeout = 10
bootstrap_resolvers = ['1.1.1.1:53']
server_names = ['codoh-test-target']
odoh_servers = true

# Trust the test CA
[doh_client_x509_auth]
creds = [{ server_name = '*', root_ca = '/tmp/test-ca.pem' }]

# Route through the CODoH proxy relay
[anonymized_dns]
routes = [{ server_name = 'codoh-test-target', via = ['codoh-test-relay'] }]

# Enable CODoH for the target
[codoh]
enabled = true
server_names = ['codoh-test-target']
proxy_host = 'localhost:8080'

# ODoH target stamp: localhost:8443, path=/dns-query
[static.codoh-test-target]
stamp = 'sdns://BQAAAAAAAAAADmxvY2FsaG9zdDo4NDQzCi9kbnMtcXVlcnk'

# ODoH relay stamp: 127.0.0.1:8080, provider=localhost:8080, path=/proxy
[static.codoh-test-relay]
stamp = 'sdns://hQAAAAAAAAAADjEyNy4wLjAuMTo4MDgwAA5sb2NhbGhvc3Q6ODA4MAYvcHJveHk'
```

## Notes

- CODoH timeout is internally 3x the configured `timeout` (proxy pipeline: enclave IPC + target forward + chunk assembly)
- Uses `cloudflare/circl` for HPKE — same library as codoh-client
- `CODOH_COVER_COUNT=0` disables cover traffic on the target (simplifies testing)
