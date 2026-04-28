// ChatRoom Durable Object
// Manages all WebSocket connections, message history, presence, typing state

export class ChatRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sessions = new Map(); // username → WebSocket
    this.history = [];         // cached in memory, persisted to storage
    this.typing = new Set();
    this.historyLoaded = false;
  }

  async loadHistory() {
    if (this.historyLoaded) return;
    try {
      const stored = await this.state.storage.get('history');
      if (stored) this.history = stored;
    } catch {}
    this.historyLoaded = true;
  }

  async saveHistory() {
    try {
      await this.state.storage.put('history', this.history);
    } catch {}
  }

  async fetch(request) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected WebSocket', { status: 426 });
    }

    const username = request.headers.get('X-Username');
    if (!username) return new Response('No username', { status: 400 });

    // Load persisted history before doing anything
    await this.loadHistory();

    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    // If user already has a session (reconnect), close old one
    if (this.sessions.has(username)) {
      try { this.sessions.get(username).close(1000, 'Replaced by new connection'); } catch {}
    }
    this.sessions.set(username, server);

    // Send last 50 messages as history to new connection
    const recentHistory = this.history.slice(-50);
    this.send(server, { type: 'history', messages: recentHistory });
    this.broadcast({ type: 'presence', online: [...this.sessions.keys()] });
    this.broadcast({ type: 'system', text: `${username} joined`, ts: Date.now() });

    server.addEventListener('message', async (event) => {
      let data;
      try { data = JSON.parse(event.data); } catch { return; }

      if (data.type === 'message') {
        if (!data.text || typeof data.text !== 'string') return;
        const text = data.text.trim().slice(0, 1000);
        if (!text) return;

        const msg = { username, text, ts: Date.now() };
        this.history.push(msg);
        // Keep last 200 messages in storage
        if (this.history.length > 200) this.history = this.history.slice(-200);

        // Persist to storage (don't await — fire and forget for speed)
        this.saveHistory();

        this.typing.delete(username);
        this.broadcastTyping();
        this.broadcast({ type: 'message', ...msg });
      }

      if (data.type === 'typing') {
        if (data.typing) this.typing.add(username);
        else this.typing.delete(username);
        this.broadcastTyping();
      }
    });

    server.addEventListener('close', () => {
      this.sessions.delete(username);
      this.typing.delete(username);
      this.broadcastTyping();
      this.broadcast({ type: 'presence', online: [...this.sessions.keys()] });
      this.broadcast({ type: 'system', text: `${username} left`, ts: Date.now() });
    });

    server.addEventListener('error', () => {
      this.sessions.delete(username);
      this.typing.delete(username);
    });

    return new Response(null, { status: 101, webSocket: client });
  }

  send(ws, data) {
    try { ws.send(JSON.stringify(data)); } catch {}
  }

  broadcast(data) {
    const msg = JSON.stringify(data);
    for (const ws of this.sessions.values()) {
      try { ws.send(msg); } catch {}
    }
  }

  broadcastTyping() {
    this.broadcast({ type: 'typing', users: [...this.typing] });
  }
}
