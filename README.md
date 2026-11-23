# traefik-mcp-go

A small, read-only [Model Context Protocol](https://modelcontextprotocol.io) server for the [Traefik](https://traefik.io) API, written in Go.

- **Read-only**: entry points, routers, services, middlewares (HTTP, TCP, UDP) and certificates
- **Troubleshooting tools**: one-call `health_report`, `find_route` (which router handles a URL, full chain to the backend) and `check_tls_endpoint` (certificate actually served)
- **Several Traefik instances** in one server (`instance` parameter on every tool)
- **Transports**: stdio, Streamable HTTP (`/mcp`) and legacy HTTP+SSE (`/sse`)
- **Bearer token auth** for the HTTP transports (several tokens possible, for rotation)
- **Upstream auth** towards Traefik: Basic Auth, Bearer token or custom headers (e.g. ForwardAuth / Cloudflare Access)
- **Small image**: static binary on `scratch`, about 10 MB, multi-arch (amd64, arm64, arm/v7)
- Portable tool schemas (no `$ref`, no type arrays), so it works with Claude, ChatGPT/OpenAI, Gemini, Cursor, VS Code, Codex, Hermes and other MCP clients
- Tested against Traefik v3.7 and v2.11 (`list_certificates` needs v3.7+)

## Tools

**Inventory**

| Tool | Purpose |
|---|---|
| `list_instances` | Configured instances, reachability and Traefik version |
| `get_overview` | Counts of routers/services/middlewares per protocol incl. warnings/errors, providers, features |
| `list_entrypoints` / `get_entrypoint` | Address, port, protocol, HTTP→HTTPS redirect, default TLS, entry point middlewares, forwardedHeaders, proxyProtocol |
| `list_routers` / `get_router` | Routers (`protocol` http/tcp/udp), filter by `search`, `status`, `service`, `middleware`; paginated |
| `list_services` / `get_service` | Services with servers, `serverStatus` (UP/DOWN) and `usedBy` |
| `list_middlewares` / `get_middleware` | Middlewares (http/tcp) with type, config and `usedBy` |
| `list_certificates` | Certificates with SANs, issuer, expiry and `days_left`, sorted by expiry; filter by domain or `expiring_within_days` (Traefik 3.7+, metadata only) |

**Troubleshooting**

| Tool | Purpose |
|---|---|
| `health_report` | One call for one or all instances (`all_instances`). Findings sorted by severity: disabled routers/services/middlewares and warnings with Traefik's error text, backends DOWN (all or partially), expired/soon expiring certificates (`cert_warn_days`), ghost routers (Docker default rule `Host(<service>-<project>)` because a rule label is missing), routers served over plain HTTP without redirect (info) |
| `find_route` | Which router handles `https://host/path`? Evaluates `Host`, `HostRegexp`, `Path`, `PathPrefix`, `PathRegexp`, `Method` and TCP `HostSNI`/`HostSNIRegexp` (v2 and v3 syntax) with router priorities. Returns the chain entry point → router → middlewares (entry point middlewares first) → service (incl. weighted/failover children) → servers with UP/DOWN. TCP routers (e.g. TLS passthrough) take precedence, entry point redirects are reported, matchers on headers/query/client IP are flagged as `unknown` |
| `check_tls_endpoint` | TLS handshake against `host:port` (optional SNI): served certificate, chain and hostname verification, TLS version, ALPN, detection of `TRAEFIK DEFAULT CERT`, and whether the certificate is in a Traefik store |

Notes:
- Names carry a provider suffix (`whoami@docker`). `get_*` also accepts the bare name and resolves it when it is unique.
- List results drop the noisy `observability` / `priorityStr` fields unless `full=true`.
- If a list result contains `next_page`, call again with `page=<next_page>`.
- `status` is one of `enabled`, `disabled`, `warning`. Disabled or warning objects carry an `error` list.
- The `service` / `middleware` filters work on Traefik v2 too (filtered by the server, not by Traefik).
- `find_route` works on the API data only; it never sends a request to the URL.

## Configuration

All settings come from environment variables (most also exist as flags, see `traefik-mcp -h`).
Secrets are only read from the environment or from files (`<VAR>_FILE`), never from flags.

### Traefik instances

**One instance:**

| Variable | Description |
|---|---|
| `TRAEFIK_URL` | Base URL of the Traefik API, e.g. `https://traefik.example.com` or `http://traefik:8080` (`/api` suffix optional) |
| `TRAEFIK_INSTANCE_NAME` | Name shown to the agent (default `default`) |
| `TRAEFIK_BASIC_USER` / `TRAEFIK_BASIC_PASSWORD` | Basic Auth |
| `TRAEFIK_BEARER_TOKEN` | `Authorization: Bearer …` (mutually exclusive with Basic Auth) |
| `TRAEFIK_HEADERS` | Extra headers, `Name: value; Other: value` |
| `TRAEFIK_TIMEOUT` | Request timeout (default `15s`) |
| `TRAEFIK_INSECURE_SKIP_VERIFY` | Skip TLS verification (default `false`) |
| `TRAEFIK_CA_FILE` | Additional CA bundle (PEM) |

**Several instances:** list the names in `TRAEFIK_INSTANCES` and use `TRAEFIK_<NAME>_…` for each one
(name upper-cased, `-` becomes `_`). `TRAEFIK_TIMEOUT`, `TRAEFIK_INSECURE_SKIP_VERIFY` and `TRAEFIK_CA_FILE` act as defaults.

```sh
TRAEFIK_INSTANCES=edge,lan
TRAEFIK_DEFAULT_INSTANCE=edge          # optional, default: first instance
TRAEFIK_EDGE_URL=https://traefik.example.com
TRAEFIK_EDGE_BASIC_USER=mcp
TRAEFIK_EDGE_BASIC_PASSWORD_FILE=/run/secrets/edge_pw
TRAEFIK_LAN_URL=http://192.168.1.10:8080
TRAEFIK_LAN_BEARER_TOKEN=...
```

Every `*_PASSWORD`, `*_BEARER_TOKEN` and `*_HEADERS` variable also has a `_FILE` variant. Credentials in the URL (`https://user:pass@host`) are rejected; use `*_BASIC_USER`/`*_BASIC_PASSWORD`.

Boolean variables accept `true`/`false` (also `1`/`0`); any other value (e.g. `off`) stops the server with an error instead of silently using the default.

### MCP server

| Variable | Default | Description |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` (`http` in the image) | `stdio` or `http` |
| `MCP_HTTP_ADDR` | `:8080` | Listen address |
| `MCP_HTTP_PATH` | `/mcp` | Streamable HTTP endpoint |
| `MCP_HTTP_ENABLE_SSE` | `true` | Also serve legacy SSE on `/sse` |
| `MCP_HTTP_STATELESS` | `false` | Stateless Streamable HTTP (no session ID) |
| `MCP_HTTP_JSON_RESPONSE` | `false` | `application/json` instead of SSE streams |
| `MCP_HTTP_SESSION_TIMEOUT` | `30m` | Idle session timeout (`0` disables) |
| `MCP_AUTH_TOKEN` / `MCP_AUTH_TOKEN_FILE` | – | Bearer token(s), comma separated, at least 16 characters. **Required for http** |
| `MCP_ALLOW_NO_AUTH` | `false` | Explicitly allow http without a token. Then only `Host` headers `localhost`/loopback and `MCP_ALLOWED_HOSTS` are accepted (DNS-rebinding protection) |
| `MCP_ALLOWED_HOSTS` | – | Extra `Host` names (comma separated, port ignored) accepted by `/mcp` and `/sse`, e.g. `traefik-mcp,mcp.example.com`. Required for non-local access without a token; optional extra check with a token |
| `TOOL_PREFIX` | – | Prefix for tool names, e.g. `traefik_` |
| `DEFAULT_PER_PAGE` | `100` | Default page size |
| `CERT_WARN_DAYS` | `21` | `health_report` warns about certificates expiring within this many days |
| `TLS_CHECK_ENABLED` | `true` | Expose `check_tls_endpoint` (`false` removes the tool) |
| `TLS_CHECK_ALLOW_CIDRS` | – | Internal ranges `check_tls_endpoint` may connect to, e.g. `192.168.100.0/24,10.0.0.5`. By default loopback, private (RFC 1918, ULA), link-local/metadata, CGNAT and other reserved addresses are refused |
| `LOG_LEVEL` / `LOG_FORMAT` | `info` / `text` | Logs always go to stderr |

HTTP endpoints: `/mcp` and `/sse` (protected), `/healthz` (liveness), `/readyz` (503 if any instance is unreachable; only reports instance names).

Generate a token: `openssl rand -hex 32`.

## Usage

### Docker (HTTP)

```sh
docker run -d --name traefik-mcp -p 8080:8080 \
  -e TRAEFIK_URL=https://traefik.example.com \
  -e TRAEFIK_BASIC_USER=mcp -e TRAEFIK_BASIC_PASSWORD=secret \
  -e MCP_AUTH_TOKEN=$(openssl rand -hex 32) \
  ghcr.io/virtualben89/traefik-mcp-go:latest
```

See [`examples/docker-compose.yml`](examples/docker-compose.yml) for a multi-instance setup with a token file.

Client configuration (Streamable HTTP):

```json
{
  "mcpServers": {
    "traefik": {
      "url": "https://traefik-mcp.example.com/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

### stdio (local binary or `docker run -i`)

```json
{
  "mcpServers": {
    "traefik": {
      "command": "traefik-mcp",
      "env": {
        "TRAEFIK_URL": "https://traefik.example.com",
        "TRAEFIK_BASIC_USER": "mcp",
        "TRAEFIK_BASIC_PASSWORD": "secret"
      }
    }
  }
}
```

With Docker: `"command": "docker", "args": ["run", "-i", "--rm", "-e", "MCP_TRANSPORT=stdio", "-e", "TRAEFIK_URL=…", "ghcr.io/virtualben89/traefik-mcp-go:latest"]`.

Binaries for Linux, macOS and Windows are attached to each [release](https://github.com/virtualben89/traefik-mcp-go/releases).

## Traefik side

The server needs the Traefik API (`api: {}` in the static config). Do not expose `api.insecure` to untrusted networks;
publish the API through a router on `api@internal` protected by Basic Auth, ForwardAuth or an IP allow list, and give this server its own credentials.

## Security

- The Traefik API is read-only by design; this server exposes no write operations.
- `check_tls_endpoint` is the only tool that connects somewhere other than the configured Traefik APIs (a TLS handshake, no HTTP request). It refuses internal addresses (checked after DNS resolution) unless they are listed in `TLS_CHECK_ALLOW_CIDRS`; disable it completely with `TLS_CHECK_ENABLED=false`.
- The upstream client never follows redirects, so credentials only reach the configured Traefik URL.
- Browser cross-origin requests to `/mcp` and `/sse` are rejected (`Sec-Fetch-Site`/`Origin`). Without a token the `Host` header must be loopback or in `MCP_ALLOWED_HOSTS`.
- A failing tool call returns an error result; panics are caught and never stop the server. Pagination is limited to `per_page` ≤ 500 and `page` ≤ 1,000,000; rules longer than 64 KiB or nested deeper than 100 levels are reported as unparseable.
- `get_middleware` returns middleware configuration as Traefik exposes it. That can include Basic Auth user hashes.
- Bearer tokens are compared in constant time (SHA-256 digests). Without `MCP_AUTH_TOKEN` the HTTP transport refuses to start unless `MCP_ALLOW_NO_AUTH=true`.
- The container runs as UID 65532 on `scratch` (no shell).

## Development

```sh
go test -race ./...
# integration against a real Traefik:
docker run -d -p 8080:8080 -v "$PWD/testdata/traefik:/etc/traefik:ro" traefik:v3.7
TRAEFIK_TEST_URL=http://localhost:8080 go test -tags integration ./internal/tools/
```

## License

MIT
