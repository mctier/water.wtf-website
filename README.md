# water.wtf — community config backend

A small HTTP API that stores community-submitted client configs and serves the approved
ones as JSON. The in-game **Community** tab reads the browse endpoint; a built-in web page
lets people submit and copy configs.

## Endpoints

| Method | Path | Who | Purpose |
|---|---|---|---|
| `GET`  | `/configs?limit=N` | public | Approved configs, newest first. **Point the client's `COMMUNITY_URL` here.** |
| `GET`  | `/configs/:id` | public | One approved config. |
| `POST` | `/configs` | public (rate-limited) | Submit `{name, author, desc, code}`. Goes to *pending* unless `AUTO_APPROVE=1`. |
| `POST` | `/configs/:id/download` | public | Increment a download counter. |
| `GET`  | `/admin/pending` | admin token | List submissions awaiting review. |
| `POST` | `/admin/:id/approve` | admin token | Approve a submission. |
| `DELETE` | `/admin/:id` | admin token | Delete any config. |
| `GET`  | `/health` | public | Liveness check. |
| `GET`  | `/` | public | Browse + submit web page. |

The `GET /configs` response is exactly what the client expects — an array of
`{ name, author, desc, code, id, downloads, created_at }` (the client uses `name/author/desc/code`).

## Run locally

```bash
cd community-backend
cp .env.example .env        # then edit .env
npm install
npm start
```

Open `http://localhost:8787`. Moderation calls need the token header:

```bash
curl -H "x-admin-token: $ADMIN_TOKEN" http://localhost:8787/admin/pending
curl -X POST -H "x-admin-token: $ADMIN_TOKEN" http://localhost:8787/admin/<id>/approve
```

## Deploy

Any Node 18+ host works (Render, Railway, Fly.io, a VPS behind nginx/Caddy). Requirements:

1. **Serve over HTTPS** — terminate TLS at a proxy or the platform. The app trusts one proxy hop
   (`trust proxy = 1`) so per-IP rate limiting uses the real client IP.
2. Set env vars: `NODE_ENV=production`, a long random `ADMIN_TOKEN`, a fixed `IP_SALT`,
   and a persistent `DB_PATH` (a mounted disk) so the SQLite file and WAL survive restarts.
3. Generate secrets:
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"   # ADMIN_TOKEN
   node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"   # IP_SALT
   ```

## Wire up the client

In `src/client/java/com/utilitymod/pulseui/ui/PulseScreen.java` set:

```java
private static final String COMMUNITY_URL = "https://your-host.example/configs";
```

Rebuild the jar/DLL. The Community tab then shows the bundled presets **plus** everything
approved on your backend. (Remote entries carry a `code`, so they Load via the share-code import.)

## Security notes (the 12-step checklist)

- **Secrets in env vars only** (`ADMIN_TOKEN`, `IP_SALT`) — never in code or the client.
- **Parameterized SQL** everywhere (better-sqlite3 prepared statements) — no string-built queries.
- **Rate limiting**: 5 submits / 10 min and 20 / day per IP; 60 download pings / min.
- **Input validation**: field length caps, control-char rejection, and the config must be a
  `UM1-` share code or valid JSON; JSON body capped at 32 KB.
- **Server-side authorization** on every `/admin/*` route via a constant-time token check.
- **helmet** security headers; `x-powered-by` removed; **no stack traces** sent to clients in prod.
- **No PII**: submitter IPs are stored only as a salted HMAC.
- Keep dependencies patched (`npm audit`), and never commit `.env` or the `.db` files (see `.gitignore`).
```
