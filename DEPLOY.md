# Aurora Chat — Deploy Guide

## Prerequisites
- Node.js installed (any recent version)
- Cloudflare account (free at cloudflare.com)

---

## Step 1 — Install Wrangler & login

```bash
npm install -g wrangler
wrangler login
```
This opens a browser tab to authorize Wrangler with your Cloudflare account.

---

## Step 2 — Install dependencies

```bash
cd aurora-chat
npm install
```

---

## Step 3 — Create the KV namespace

```bash
wrangler kv:namespace create "USERS"
wrangler kv:namespace create "USERS" --preview
```

Each command prints an `id`. Copy them into `wrangler.toml`:
- Replace `REPLACE_WITH_KV_ID` with the first id
- Replace `REPLACE_WITH_KV_PREVIEW_ID` with the preview id

---

## Step 4 — Set your JWT secret

Pick any long random string (32+ characters). Then:

```bash
wrangler secret put JWT_SECRET
```
Paste your secret when prompted. This is stored securely in Cloudflare — never in your code.

---

## Step 5 — Deploy

```bash
wrangler deploy
```

Wrangler will print your Worker URL, something like:
`https://aurora-chat.YOUR_SUBDOMAIN.workers.dev`

---

## Step 6 — Add the URL to Aurora dashboard

Open the Aurora dashboard → ⚙ Settings → **Chat API URL**
Paste your Worker URL (without trailing slash).

---

## Local development (optional)

```bash
wrangler dev
```
Runs the Worker locally at `http://localhost:8787`.
Note: Durable Objects run remotely even in dev mode.

---

## Troubleshooting

**"Durable Object class not found"** — make sure `wrangler.toml` has the `[[migrations]]` block and you've deployed at least once.

**WebSocket connects but immediately closes** — check that JWT_SECRET is set (`wrangler secret list`).

**"KV namespace not found"** — make sure the IDs in wrangler.toml match what `kv:namespace create` printed.
