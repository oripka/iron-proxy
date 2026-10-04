# Native QUIC inspection v1

Opt-in companion for Nosy's authenticated, firewall-admitted native flows:
`--nosy-inspection --nosy-quic`. `--nosy-quic-version` returns `1`. This is not
an open UDP proxy and cannot be combined with managed or mandatory v2 per-run
inspection. It uses quic-go v0.63.0 / Go 1.26, not PacketSafari's passive crypto.

The authenticated HTTP listener accepts `POST /nosy/quic`, validates original
numeric destination, hostname, process/app hashes, flow and revision, then
hijacks a byte stream. A two-byte big-endian length precedes each UDP datagram.
The provider must derive identity from the OS audit token and protect the
session bearer credential. Engine trust in that credential is not permission
to skip current connection rules. IP and hostname allowlist/deny-CIDR checks
precede all upstream dials, including compatibility relay.

One channel owns one client QUIC transport and one isolated upstream HTTP/3
transport. SNI, request authority and original endpoint are bound. No shared
cross-app/upstream connection pool, 0-RTT acceptance, destination migration,
WebTransport, extended CONNECT, H3 datagrams, or pre-termination replay fallback.
v1/v2 clients are accepted; upstream is v1. Missing usable provider hostname,
ECH-obscured identity and other ALPNs are explicit unsupported coverage.

The existing CA cache, HTTP policy/audit pipeline and bounded outbound privacy
observer are shared with TCP. Request/response bodies stream with backpressure;
EOF publishes request trailers before the upstream sends its trailing HEADERS.
Cancellation reaches the independent upstream request. Normal upstream trust
verification is mandatory. Upstream mTLS is unsupported and never trains an
exception. Standalone native audit output excludes URL paths, payloads and raw errors.
SSE responses flush events before stream completion and preserve final response
trailers through the shared TCP/HTTP/3 streaming path.

Only demonstrated remote certificate alerts train the shared bounded cache:
transport + process instance + signed application + hostname + original IP:port,
ten minutes, at most 4,096 entries. A subsequent allowed connection relays
unchanged. There is no claim of proven pinning or seamless recovery of the first
attempt. Empty/non-allowlist pipelines and mandatory v2 policy cannot relay
opaquely. `POST /nosy/compatibility/reset` with the session bearer clears the
cache. It grants no network permission. EOF, timeouts, malformed packets,
upstream errors and engine unavailability never train exceptions.

Bounds: 64 QUIC channels, one admitted connection per channel, 32 incoming
request streams, 512 shared HTTP slots, 32 KiB headers, 256 KiB stream / 1 MiB
connection receive windows, 65,507-byte datagrams, three-second packet writes
and handshake idle timeout, 30-second idle and ten-minute channel lifetime.
Listener health/session failure semantics belong to Nosy, not this exception
cache. Do not expose credentials or test key logs in normal diagnostics.

Both incoming request and upstream response headers have the 32 KiB limit.
Parsed requests rejected before the shared HTTP pipeline emit one admission
audit with a fixed `native_http3_*` reason and request ID. Such records do not
claim HTTP rules were evaluated. Capacity failures are errors, not firewall
denials; authority rejections record only the admitted hostname.

## Isolated tests

No installed provider, CA trust changes or real network interception required:

```sh
go test -race ./internal/proxy ./internal/transform ./cmd/iron-proxy
NOSY_TEST_CHROMIUM=/path/to/headless_shell go test ./internal/proxy -run TestNativeQUICBrowser -count=1 -v
NOSY_QUIC_LOAD=1 go test ./internal/proxy -run TestNativeQUICSustainedLoad -count=1 -v
NOSY_QUIC_EVIDENCE_DIR=/absolute/private/new-directory NOSY_TEST_TSHARK=/path/to/tshark go test ./internal/proxy -run TestNativeQUICPacketEvidence -count=1 -v
```

The browser test pins only a disposable leaf SPKI in a disposable profile. It
forces local H3, suppresses background networking/DNS and verifies a page plus
eight POSTs. Its local datagram adapter is not a substitute for the signed
Network Extension. The packet test requires a fresh directory, writes files
0600, and proves encrypted H3 with/without keys, including the initial CID
transition. Its setup/proof payload follows PacketSafari's
`capture-probe/qualification/linux/tlsfixture/quic/main.go`; no passive decoder
was transplanted. TShark is an independent oracle. Test secrets never enter
production log output. Optional browser/evidence/load tests skip explicitly
without their environment variables.

Native signed-host acceptance and measured results are recorded in
`../guard/docs/http3-inspection.md`. Do not claim that acceptance passed from
these loopback tests. Check browser/Codex sign-in, coexistence, trust stores,
provider attribution, idle CPU/RSS, crash/restart/sleep and policy changes
against the exact signed candidate, with separate user authorization.
