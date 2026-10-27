# lookout

lookout watches the traffic that enters and leaves a server. It tells people, honest bots and hostile AI agents apart. It suggests what to do about each one, and enforces what you approve.

It has three parts:

1. **`lookout-sensor`** runs on the box. It is a reverse proxy in front of your app. It records every request with its TLS fingerprint (JA4). With `-egress`, an eBPF probe also records every outbound TCP connection. The sensor enforces the decisions that you approve.
2. **`lookout-server`** collects the sensor data in SQLite. It groups requests into *actors* (one IP with one TLS fingerprint). It checks who each actor claims to be, scores the actors with rules, and asks an LLM about the interesting ones.
3. **The dashboard** is served by `lookout-server`. It calls actors *visitors*. It has four tabs:
   - **Visitors** lists them by risk. Each visitor page shows what lookout thinks it is, why, and what you can do about it.
   - **Review** holds the suggestions that wait for your approval, the decisions in force, and their history.
   - **Outbound** lists the outbound connections from your servers.
   - **Sensors** manages sensor keys.

## How an actor is judged

1. **Identity.** A declared crawler is checked with forward-confirmed reverse DNS (Googlebot, Bingbot, Applebot and others). A signed AI agent is checked with [Web Bot Auth](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/) (HTTP Message Signatures, Ed25519). A claim that proves false is scored as hostile.
2. **Rules.** Rules are cheap and run on every actor. Examples:
   - The client claims to be Chrome, but its TLS handshake is not a browser's.
   - The client claims to be a browser but sends no `Sec-Fetch-*` headers.
   - Pages are fetched, but CSS, JS and images are never loaded.
   - The client asks for `text/markdown`, or pauses irregularly between pages like an LLM agent.
   - Requests arrive at clockwork timing.
   - The client walks numeric IDs, or probes for `/.env`, `/.git/`, SQL injection and similar.
   - A browser automation tool reports `navigator.webdriver` at the challenge.
3. **LLM triage.** The model reads each actor that scores 25 or more. It runs through OpenRouter (default model: DeepSeek V4.1 Flash) or the Anthropic API (default model: Claude Opus 5.5). It gets the rule results and up to 80 raw requests. It returns a classification, a risk score, evidence, and a recommended action. Calls are capped per hour.
4. **Decisions.** A recommendation of block, challenge or rate limit becomes a *suggestion*. Nothing is enforced until you approve it. A rejected suggestion does not come back for a day. Without an API key, the rules make the suggestions instead (score 80 or more).

The **challenge** is a JavaScript proof-of-work page. Real browsers pass it in about a second. Plain HTTP clients and default headless browsers fail it.

## Run it

Requirements: Go 1.27 and Bun. Egress capture needs Linux 5.8 or later, and root (or CAP_BPF and CAP_PERFMON).

```sh
# Build the dashboard, then the binaries (the server embeds the dashboard).
(cd web && bun install --frozen-lockfile && bun run build)
go build -o bin/ ./cmd/...

# Start the server.
export LOOKOUT_ADMIN_TOKEN=$(openssl rand -hex 24)   # keep this; it signs you in
export OPENROUTER_API_KEY=...                         # optional; turns on LLM triage
bin/lookout-server
```

Open <http://127.0.0.1:8080>. Sign in with the admin token. Go to **Sensors** and create a key. The dashboard shows the exact command for the sensor, for example:

```sh
LOOKOUT_KEY=lk_... bin/lookout-sensor \
  -server https://lookout.internal:8080 \
  -upstream http://127.0.0.1:3000 \
  -listen :443 -domain shop.example.com \
  -egress
```

Point your DNS (or load balancer) at the sensor instead of the app.

### Server settings

| Variable | Default | Meaning |
|---|---|---|
| `LOOKOUT_ADMIN_TOKEN` | required | Dashboard sign-in. 16 characters or more. Changing it signs everyone out. |
| `OPENROUTER_API_KEY` | unset | Turns on LLM triage through OpenRouter. |
| `ANTHROPIC_API_KEY` | unset | Turns on LLM triage through the Anthropic API. Set only one of the two keys. |
| `LOOKOUT_LLM_MODEL` | `deepseek/deepseek-v4.1-flash` (OpenRouter), `claude-opus-5-5` (Anthropic) | Triage model. |
| `LOOKOUT_LLM_EFFORT` | `medium` | Reasoning effort: `low`, `medium` or `high` (Anthropic also takes `xhigh` and `max`). |
| `LOOKOUT_OPENROUTER_URL` | `https://openrouter.ai/api/v1` | Any OpenAI-compatible chat completions API. |
| `LOOKOUT_TRIAGE_PER_HOUR` | `120` | Maximum LLM calls per hour. |
| `LOOKOUT_TRIAGE_MIN_SCORE` | `25` | The rule score that sends an actor to the LLM. |
| `LOOKOUT_RETENTION_DAYS` | `7` | How long requests are kept. |
| `LOOKOUT_ADDR` | `127.0.0.1:8080` | Listen address. Put TLS in front of it if sensors reach it over a network. |
| `LOOKOUT_DB` | `lookout.db` | SQLite file. |

### Sensor flags

| Flag (env) | Meaning |
|---|---|
| `-upstream` (`LOOKOUT_UPSTREAM`) | Your app. |
| `-server` (`LOOKOUT_SERVER`) | The lookout-server URL. |
| `LOOKOUT_KEY` | Sensor key. Environment only, so it never appears in `ps`. |
| `-listen` (`LOOKOUT_LISTEN`) | Default `:8443`. |
| `-domain` (`LOOKOUT_DOMAIN`) | Gets Let's Encrypt certificates automatically (TLS-ALPN-01 on port 443). |
| `-tls-cert`, `-tls-key` | Use your own certificate. Without TLS, there are no fingerprints. |
| `-trust-proxy` (`LOOKOUT_TRUST_PROXY`) | CIDRs of your CDN or load balancer. Their `X-Forwarded-For` is trusted. |
| `-egress` (`LOOKOUT_EGRESS=1`) | Record outbound connections with eBPF. |

## Develop

```sh
go test ./tests/...                                  # all Go tests
go test -c -o /tmp/egress.test ./tests/egress && sudo /tmp/egress.test   # eBPF probe (root)
cd web && bun run dev                                # dashboard on :5180, proxies /api to :8080
cd web && bun run lint && bun run typecheck
```

Tests live in `tests/<module>/`.

## Layout

```
cmd/lookout-sensor   sensor binary
cmd/lookout-server   server binary
event/               wire format between sensor and server
sensor/              proxy, JA4, challenge, enforcement, shipping
sensor/egress/       eBPF probe (Go assembler; no C toolchain)
server/              engine (analyze, triage, suggest) and HTTP API
server/analyze/      rules and known agents
server/verify/       reverse DNS and Web Bot Auth
server/triage/       LLM triage (OpenRouter, Anthropic)
server/store/        SQLite
web/                 dashboard (React, TanStack Query, Tailwind)
```

## Limits

- The sensor sees inbound HTTP in full. For outbound traffic, it sees TCP connections only (process, destination, port), not their content.
- Behind a CDN that terminates TLS, the JA4 fingerprint is the CDN's. Run the sensor where TLS terminates, or accept weaker signals.
- Header order is not recorded. Go's HTTP server does not expose it.
- Request bodies are not recorded. Query values with sensitive names (`token`, `password`, `key`, and similar) are redacted at the sensor.
- Web Bot Auth verification supports Ed25519 keys and the `directory` Signature-Agent type.
