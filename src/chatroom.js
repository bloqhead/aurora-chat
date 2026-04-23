// ChatRoom Durable Object
// Manages all WebSocket connections, message history, presence, typing state

export class ChatRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sessions = new Map(); // username → WebSocket
    this.history = [];         // last 100 messages
    this.typing = new Set();   // usernames currently typing
  }

  async fetch(request) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected WebSocket', { status: 426 });
    }

    const username = request.headers.get('X-Username');
    if (!username) return new Response('No username', { status: 400 });

    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    // If user already has a session (reconnect), close old one
    if (this.sessions.has(username)) {
      try { this.sessions.get(username).close(1000, 'Replaced by new connection'); } catch {}
    }
    this.sessions.set(username, server);

    // Send history + presence to new connection
    this.send(server, { type: 'history', messages: this.history });
    this.broadcast({ type: 'presence', online: [...this.sessions.keys()] });
    this.broadcast({ type: 'system', text: `${username} joined`, ts: Date.now() });

    server.addEventListener('message', async (event) => {
      let data;
      try { data = JSON.parse(event.data); } catch { return; }

      if (data.type === 'message') {
        if (!data.text || typeof data.text !== 'string') return;
        const text = data.text.trim().slice(0, 1000); // max 1000 chars
        if (!text) return;

        const msg = { username, text, ts: Date.now() };
        this.history.push(msg);
        if (this.history.length > 100) this.history.shift();

        // Clear typing when message sent
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
