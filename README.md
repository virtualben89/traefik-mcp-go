# traefik-mcp-go

A small, read-only [Model Context Protocol](https://modelcontextprotocol.io) server for the [Traefik](https://traefik.io) API, written in Go.

- **Read-only**: routers, services and middlewares for HTTP, TCP and UDP, list and detail views
- **Several Traefik instances** in one server (`instance` parameter on every tool)
- **Transports**: stdio, Streamable HTTP (`/mcp`) and legacy HTTP+SSE (`/sse`)
- **Bearer token auth** for the HTTP transports (several tokens possible, for rotation)
- **Upstream auth** towards Traefik: Basic Auth, Bearer token or custom headers (e.g. ForwardAuth / Cloudflare Access)
- **Small image**: static binary on `scratch`, about 10 MB, multi-arch (amd64, arm64, arm/v7)
- Portable tool schemas (no `$ref`, no type arrays), so it works with Claude, ChatGPT/OpenAI, Gemini, Cursor, VS Code, Codex, Hermes and other MCP clients
- Tested against Traefik v3.7 and v2.11

## Tools

| Tool | Purpose |
|---|---|
| `list_instances` | Configured instances, reachability and Traefik version |
| `list_routers` | Routers (`protocol` http/tcp/udp), filter by `search`, `status`, `service`, `middleware`; paginated |
| `get_router` | Router details: rule, entryPoints, middlewares, service, TLS/certResolver, errors |
| `list_services` | Services with servers, `serverStatus` (UP/DOWN) and `usedBy` |
| `get_service` | Service details |
| `list_middlewares` | Middlewares (http/tcp) with type, config and `usedBy` |
| `get_middleware` | Middleware details |

Notes:
- Names carry a provider suffix (`whoami@docker`). `get_*` also accepts the bare name and resolves it when it is unique.
- List results drop the noisy `observability` / `priorityStr` fields unless `full=true`.
- If a list result contains `next_page`, call again with `page=<next_page>`.
- `status` is one of `enabled`, `disabled`, `warning`. Disabled or warning objects carry an `error` list.
- The `service` / `middleware` filters work on Traefik v2 too (filtered by the server, not by Traefik).

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

Every `*_PASSWORD`, `*_BEARER_TOKEN` and `*_HEADERS` variable also has a `_FILE` variant.

### MCP server

| Variable | Default | Description |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` (`http` in the image) | `stdio` or `http` |
| `MCP_HTTP_ADDR` | `:8080` | Listen address |
| `MCP_HTTP_PATH` | `/mcp` | Streamable HTTP endpoint |
| `MCP_HTTP_ENABLE_SSE` | `true` | Also serve legacy SSE on `/sse` |
| `MCP_HTTP_STATELESS` | `false` | Stateless Streamable HTTP (no session ID) |
| `MCP_HTTP_JSON_RESPONSE` | `false` | `application/json` instead of SSE streams |
| `MCP_HTTP_SESSION_TIMEOUT` | `30m` | Idle session timeout |
| `MCP_AUTH_TOKEN` / `MCP_AUTH_TOKEN_FILE` | – | Bearer token(s), comma separated, at least 16 characters. **Required for http** |
| `MCP_ALLOW_NO_AUTH` | `false` | Explicitly allow http without a token |
| `TOOL_PREFIX` | – | Prefix for tool names, e.g. `traefik_` |
| `DEFAULT_PER_PAGE` | `100` | Default page size |
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
