const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const path = require('path');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');

const BCRYPT_ROUNDS = 12; // cost factor — strong but not too slow

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json());
app.use(cookieParser('samegame-secret-2024'));
app.use(express.static(path.join(__dirname, 'public')));

// ── Database ──────────────────────────────────────────────────────────────────
const adapter = new FileSync('db.json');
const db = low(adapter);
db.defaults({
  players: [],
  accounts: [],
  messages: [],
  private_rooms: [],
  bans: [],
  mutes: [],
  admin_logs: [],
}).write();

// ── Constants ─────────────────────────────────────────────────────────────────
const GAME_TYPES = ['dodge', 'breakout', 'memory', 'quiz', 'snake', 'tetris', 'flappy', 'bubble'];
const PUBLIC_ROOMS = ['arcade', 'lounge', 'arena', 'tavern', 'dungeon', 'nexus'];
const ROOM_MAX = 20;
const ADMIN_USERNAME = 'Loup007A';
const ADMIN_SALT = 'samegame-admin-salt-2024';

function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

// Ensure admin account exists with bcrypt hash
async function seedAdmin() {
  const existing = db.get('accounts').find({ username: ADMIN_USERNAME }).value();
  if (!existing) {
    const passwordHash = await bcrypt.hash('MotDePasseAdmin123#@', BCRYPT_ROUNDS);
    db.get('accounts').push({
      id: 'admin-' + uuidv4(),
      username: ADMIN_USERNAME,
      passwordHash,
      isAdmin: true,
      hashType: 'bcrypt',
      createdAt: Date.now(),
    }).write();
    console.log('✓ Admin account created (bcrypt)');
  } else if (existing.hashType !== 'bcrypt') {
    // Migrate legacy SHA-256 admin hash to bcrypt
    const passwordHash = await bcrypt.hash('MotDePasseAdmin123#@', BCRYPT_ROUNDS);
    db.get('accounts').find({ username: ADMIN_USERNAME }).assign({ passwordHash, hashType: 'bcrypt', salt: undefined }).write();
    console.log('✓ Admin account migrated to bcrypt');
  }
}
seedAdmin();

// ── Identification (IP + cookie + fingerprint) ────────────────────────────────
function getPlayerIdentity(req) {
  const ip = (req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || '0.0.0.0').trim();
  const cookieId = req.signedCookies['sgid'] || req.cookies['sgid'] || null;
  const fingerprint = req.body?.fingerprint || req.query?.fingerprint || 'default';
  // Composite identity: if cookie exists, prioritize it; else use IP+fingerprint
  const primaryId = cookieId || sha256(`${ip}:${fingerprint}`).slice(0, 16);
  return { ip, cookieId, fingerprint, primaryId };
}

// ── Game generation ───────────────────────────────────────────────────────────
function seededRandom(seed) {
  let s = seed;
  return () => { s = (s * 1664525 + 1013904223) & 0xffffffff; return (s >>> 0) / 0xffffffff; };
}

function generateGameConfig(seed, type) {
  const rng = seededRandom(seed);
  const palettes = [
    { bg: '#0a0a1a', primary: '#ff3366', secondary: '#33ffcc', accent: '#ffcc00' },
    { bg: '#0d1117', primary: '#7c3aed', secondary: '#06b6d4', accent: '#f59e0b' },
    { bg: '#0f0f0f', primary: '#ef4444', secondary: '#22c55e', accent: '#3b82f6' },
    { bg: '#111827', primary: '#f97316', secondary: '#a855f7', accent: '#14b8a6' },
    { bg: '#1a0a2e', primary: '#ec4899', secondary: '#8b5cf6', accent: '#fbbf24' },
    { bg: '#0a1628', primary: '#00d4ff', secondary: '#ff6b35', accent: '#39ff14' },
    { bg: '#0d0a1a', primary: '#ff007f', secondary: '#00ffcc', accent: '#ffe600' },
    { bg: '#0a0f0a', primary: '#39ff14', secondary: '#ff3300', accent: '#00cfff' },
  ];
  const palette = palettes[Math.floor(rng() * palettes.length)];

  const configs = {
    dodge: {
      speed: 4 + Math.floor(rng() * 5),
      obstacleRate: 0.6 + rng() * 1.2,
      obstacleShape: ['circle', 'square', 'triangle', 'diamond', 'cross'][Math.floor(rng() * 5)],
      bgPattern: ['stars', 'grid', 'dots', 'waves', 'hex'][Math.floor(rng() * 5)],
      playerShape: ['ship', 'arrow', 'circle', 'star'][Math.floor(rng() * 4)],
      gravity: rng() > 0.4,
      gravityPull: 0.08 + rng() * 0.1,
      sideObstacles: rng() > 0.5,
      accelerates: rng() > 0.4,
      palette,
    },
    breakout: {
      rows: 5 + Math.floor(rng() * 5),
      cols: 7 + Math.floor(rng() * 5),
      ballSpeed: 4 + Math.floor(rng() * 4),
      paddleSize: 40 + Math.floor(rng() * 40),
      brickPattern: ['solid', 'checkers', 'diagonal', 'random', 'fortress'][Math.floor(rng() * 5)],
      multiball: rng() > 0.5,
      shrinkPaddle: rng() > 0.5,
      speedIncrease: rng() > 0.4,
      palette,
    },
    memory: {
      gridSize: [3, 4, 4][Math.floor(rng() * 3)],
      symbols: ['emoji', 'shapes', 'letters', 'numbers', 'kanji'][Math.floor(rng() * 5)],
      flipDelay: 400 + Math.floor(rng() * 600),
      showTime: 400 + Math.floor(rng() * 600),
      penalty: rng() > 0.5,
      timeLimit: rng() > 0.5 ? 60 + Math.floor(rng() * 60) : null,
      palette,
    },
    quiz: {
      category: ['math', 'logic', 'anagram', 'sequence', 'wordplay'][Math.floor(rng() * 5)],
      difficulty: ['medium', 'hard', 'hard'][Math.floor(rng() * 3)],
      timeLimit: 6 + Math.floor(rng() * 10),
      questionsCount: 8 + Math.floor(rng() * 10),
      seed,
      palette,
    },
    snake: {
      startSpeed: 80 + Math.floor(rng() * 60),
      speedIncrease: rng() > 0.3,
      wallWrap: rng() > 0.5,
      obstacles: rng() > 0.4,
      ghostFood: rng() > 0.5,
      palette,
    },
    tetris: {
      startSpeed: 400 + Math.floor(rng() * 300),
      speedIncrease: true,
      ghostPiece: rng() > 0.3,
      invisibleMode: rng() > 0.7,
      randomRotations: rng() > 0.5,
      palette,
    },
    flappy: {
      gravity: 0.25 + rng() * 0.2,
      jumpForce: -6 - rng() * 2,
      pipeGap: 120 + Math.floor(rng() * 60),
      pipeSpeed: 2.5 + rng() * 2,
      pipeInterval: 90 + Math.floor(rng() * 40),
      birdShape: ['circle', 'square', 'triangle'][Math.floor(rng() * 3)],
      palette,
    },
    bubble: {
      cols: 10 + Math.floor(rng() * 4),
      rows: 8 + Math.floor(rng() * 4),
      colors: 3 + Math.floor(rng() * 3),
      minGroup: 2 + Math.floor(rng() * 2),
      fallSpeed: 0.5 + rng() * 1.5,
      palette,
    },
  };

  return { type, seed, palette, ...configs[type] };
}

// ── Player helpers ────────────────────────────────────────────────────────────
function getOrCreatePlayer(primaryId, ip, fingerprint, accountId = null) {
  let player = db.get('players').find({ id: primaryId }).value();
  if (!player) {
    const seed = Math.floor(Math.random() * 2147483647);
    const type = GAME_TYPES[Math.floor(Math.random() * GAME_TYPES.length)];
    const room = PUBLIC_ROOMS[Math.floor(Math.random() * PUBLIC_ROOMS.length)];
    player = {
      id: primaryId, ip, fingerprint, game_seed: seed, game_type: type, room,
      score: 0, scoreMultiplier: 1, nickname: `Player_${primaryId.slice(0, 4)}`,
      accountId: accountId || null, created_at: Date.now(), last_seen: Date.now(),
      banned: false, muteUntil: 0,
    };
    db.get('players').push(player).write();
  } else {
    db.get('players').find({ id: primaryId }).assign({ last_seen: Date.now(), ip }).write();
  }
  return db.get('players').find({ id: primaryId }).value();
}

// ── Auth helpers (bcrypt) ──────────────────────────────────────────────────────
async function hashPassword(password) {
  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  return { passwordHash };
}
async function verifyPassword(password, storedHash) {
  return bcrypt.compare(password, storedHash);
}

// ── REST API ──────────────────────────────────────────────────────────────────

// Session
app.post('/api/session', (req, res) => {
  const { ip, fingerprint, primaryId } = getPlayerIdentity(req);
  const { nickname, accountId } = req.body;
  try {
    // Check ban
    const banEntry = db.get('bans').find(b => b.playerId === primaryId && (!b.expiresAt || b.expiresAt > Date.now())).value();
    if (banEntry) return res.status(403).json({ error: 'banned', reason: banEntry.reason });

    const player = getOrCreatePlayer(primaryId, ip, fingerprint, accountId);
    const config = generateGameConfig(player.game_seed, player.game_type);
    if (nickname) db.get('players').find({ id: primaryId }).assign({ nickname }).write();

    // Set persistent cookie (30 days)
    res.cookie('sgid', primaryId, { maxAge: 30 * 24 * 3600 * 1000, httpOnly: true, signed: true });

    res.json({
      playerId: player.id,
      room: player.room,
      gameConfig: config,
      nickname: nickname || player.nickname,
      scoreMultiplier: player.scoreMultiplier || 1,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Session error' });
  }
});

// Register
app.post('/api/auth/register', async (req, res) => {
  const { username, password, nickname } = req.body;
  if (!username || !password || username.length < 3 || password.length < 6) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }
  if (db.get('accounts').find({ username }).value()) {
    return res.status(409).json({ error: 'Username taken' });
  }
  const { passwordHash } = await hashPassword(password);
  const accountId = uuidv4();
  db.get('accounts').push({
    id: accountId, username, passwordHash, hashType: 'bcrypt',
    isAdmin: false, createdAt: Date.now(), nickname: nickname || username,
  }).write();
  res.json({ ok: true, accountId, username });
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const account = db.get('accounts').find({ username }).value();
  if (!account) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await verifyPassword(password, account.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  res.json({ ok: true, accountId: account.id, username: account.username, isAdmin: account.isAdmin || false, nickname: account.nickname });
});

// Score update
app.post('/api/score', (req, res) => {
  const { playerId, score } = req.body;
  const player = db.get('players').find({ id: playerId }).value();
  if (player && score > player.score) db.get('players').find({ id: playerId }).assign({ score }).write();
  res.json({ ok: true });
});

// Room scores leaderboard
app.get('/api/room/:room/scores', (req, res) => {
  const scores = db.get('players')
    .filter(p => p.room === req.params.room && !p.banned)
    .sortBy('score').reverse().take(10)
    .map(p => ({ nickname: p.nickname, score: p.score })).value();
  res.json(scores);
});

// Room chat history
app.get('/api/room/:room/history', (req, res) => {
  const msgs = db.get('messages').filter({ room: req.params.room }).takeRight(50).value();
  res.json(msgs);
});

// ── Private Rooms ──────────────────────────────────────────────────────────────
app.post('/api/private-room/create', (req, res) => {
  const { playerId, nickname } = req.body;
  const code = Math.random().toString(36).substring(2, 8).toUpperCase();
  const roomId = 'priv-' + uuidv4().slice(0, 8);
  db.get('private_rooms').push({
    id: roomId, code, createdBy: playerId, creatorNickname: nickname,
    players: [], createdAt: Date.now(),
  }).write();
  res.json({ roomId, code, link: `/join/${code}` });
});

app.post('/api/private-room/join', (req, res) => {
  const { code } = req.body;
  const room = db.get('private_rooms').find({ code: code.toUpperCase() }).value();
  if (!room) return res.status(404).json({ error: 'Room not found' });
  res.json({ roomId: room.id, code: room.code });
});

app.get('/api/private-room/:roomId', (req, res) => {
  const room = db.get('private_rooms').find({ id: req.params.roomId }).value();
  if (!room) return res.status(404).json({ error: 'Not found' });
  res.json(room);
});

// ── Admin API ─────────────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  const expected = sha256('admin-session:' + ADMIN_USERNAME + ':' + (process.env.ADMIN_SECRET || 'samegame-2024'));
  if (token !== expected) return res.status(403).json({ error: 'Forbidden' });
  next();
}

// Get all players
app.get('/api/admin/players', requireAdmin, (req, res) => {
  const players = db.get('players').value();
  res.json(players);
});

// Get all messages
app.get('/api/admin/messages', requireAdmin, (req, res) => {
  const msgs = db.get('messages').takeRight(200).value();
  res.json(msgs);
});

// Delete a message
app.delete('/api/admin/message/:id', requireAdmin, (req, res) => {
  db.get('messages').remove({ id: req.params.id }).write();
  broadcastToAll({ type: 'message_deleted', messageId: req.params.id });
  res.json({ ok: true });
});

// Edit a message
app.patch('/api/admin/message/:id', requireAdmin, (req, res) => {
  const { content } = req.body;
  db.get('messages').find({ id: req.params.id }).assign({ content, edited: true }).write();
  broadcastToAll({ type: 'message_edited', messageId: req.params.id, content });
  res.json({ ok: true });
});

// Mute player (temp)
app.post('/api/admin/mute', requireAdmin, (req, res) => {
  const { playerId, durationMinutes } = req.body;
  const muteUntil = Date.now() + durationMinutes * 60 * 1000;
  db.get('players').find({ id: playerId }).assign({ muteUntil }).write();
  broadcastToAll({ type: 'admin_action', action: 'muted', playerId, muteUntil });
  res.json({ ok: true });
});

// Ban player
app.post('/api/admin/ban', requireAdmin, (req, res) => {
  const { playerId, reason, expiresAt } = req.body;
  db.get('bans').push({ playerId, reason, expiresAt: expiresAt || null, bannedAt: Date.now() }).write();
  db.get('players').find({ id: playerId }).assign({ banned: true }).write();
  kickPlayer(playerId, 'banned');
  res.json({ ok: true });
});

// Unban
app.post('/api/admin/unban', requireAdmin, (req, res) => {
  const { playerId } = req.body;
  db.get('bans').remove({ playerId }).write();
  db.get('players').find({ id: playerId }).assign({ banned: false }).write();
  res.json({ ok: true });
});

// Change score
app.post('/api/admin/set-score', requireAdmin, (req, res) => {
  const { playerId, score } = req.body;
  db.get('players').find({ id: playerId }).assign({ score }).write();
  sendToPlayer(playerId, { type: 'admin_set_score', score });
  res.json({ ok: true });
});

// Set score multiplier
app.post('/api/admin/set-multiplier', requireAdmin, (req, res) => {
  const { playerId, multiplier } = req.body;
  db.get('players').find({ id: playerId }).assign({ scoreMultiplier: multiplier }).write();
  sendToPlayer(playerId, { type: 'admin_set_multiplier', multiplier });
  res.json({ ok: true });
});

// Force game type
app.post('/api/admin/force-game', requireAdmin, (req, res) => {
  const { playerId, gameType } = req.body;
  db.get('players').find({ id: playerId }).assign({ game_type: gameType }).write();
  sendToPlayer(playerId, { type: 'admin_force_game', gameType });
  res.json({ ok: true });
});

// Force difficulty (speed / seed override)
app.post('/api/admin/set-difficulty', requireAdmin, (req, res) => {
  const { playerId, speedMultiplier } = req.body;
  db.get('players').find({ id: playerId }).assign({ speedMultiplier: speedMultiplier }).write();
  sendToPlayer(playerId, { type: 'admin_set_difficulty', speedMultiplier });
  res.json({ ok: true });
});

// Set room
app.post('/api/admin/set-room', requireAdmin, (req, res) => {
  const { playerId, room } = req.body;
  db.get('players').find({ id: playerId }).assign({ room }).write();
  sendToPlayer(playerId, { type: 'admin_set_room', room });
  res.json({ ok: true });
});

// Teleport player (reconnect to another room)
app.post('/api/admin/teleport', requireAdmin, (req, res) => {
  const { playerId, room } = req.body;
  db.get('players').find({ id: playerId }).assign({ room }).write();
  sendToPlayer(playerId, { type: 'admin_teleport', room });
  res.json({ ok: true });
});

// Reset score to 0
app.post('/api/admin/reset-score', requireAdmin, (req, res) => {
  const { playerId } = req.body;
  db.get('players').find({ id: playerId }).assign({ score: 0 }).write();
  sendToPlayer(playerId, { type: 'admin_set_score', score: 0 });
  res.json({ ok: true });
});

// Shuffle game (new random game)
app.post('/api/admin/shuffle-game', requireAdmin, (req, res) => {
  const { playerId } = req.body;
  const newSeed = Math.floor(Math.random() * 2147483647);
  const newType = GAME_TYPES[Math.floor(Math.random() * GAME_TYPES.length)];
  db.get('players').find({ id: playerId }).assign({ game_seed: newSeed, game_type: newType }).write();
  sendToPlayer(playerId, { type: 'admin_force_game', gameType: newType, seed: newSeed });
  res.json({ ok: true });
});

// Spectate a player — returns their game config
app.get('/api/admin/spectate/:playerId', requireAdmin, (req, res) => {
  const player = db.get('players').find({ id: req.params.playerId }).value();
  if (!player) return res.status(404).json({ error: 'Player not found' });
  const config = generateGameConfig(player.game_seed, player.game_type);
  res.json({ player, config });
});

// Admin chat broadcast
app.post('/api/admin/broadcast', requireAdmin, (req, res) => {
  const { content } = req.body;
  broadcastToAll({ type: 'system', content: `[ADMIN] ${content}`, highlight: true });
  res.json({ ok: true });
});

// Get admin token
app.post('/api/admin/auth', async (req, res) => {
  const { username, password } = req.body;
  const account = db.get('accounts').find({ username }).value();
  if (!account || !account.isAdmin) return res.status(401).json({ error: 'Unauthorized' });

  const valid = await verifyPassword(password, account.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Unauthorized' });

  // Token is HMAC of username+timestamp — stateless, verifiable
  const token = sha256('admin-session:' + username + ':' + (process.env.ADMIN_SECRET || 'samegame-2024'));
  res.json({ ok: true, token });
});

// Live stats
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const totalPlayers = db.get('players').size().value();
  const totalMessages = db.get('messages').size().value();
  const onlineCount = Object.values(rooms).reduce((sum, s) => sum + s.size, 0);
  const roomCounts = {};
  PUBLIC_ROOMS.forEach(r => { roomCounts[r] = rooms[r]?.size || 0; });
  res.json({ totalPlayers, totalMessages, onlineCount, roomCounts });
});

// ── WebSocket ─────────────────────────────────────────────────────────────────
const rooms = {};        // roomName -> Set<ws>
const playerWsMap = {};  // playerId -> ws

wss.on('connection', (ws) => {
  ws.room = null; ws.playerId = null; ws.nickname = 'Anonymous'; ws.isAdmin = false;

  ws.on('message', (raw) => {
    let msg; try { msg = JSON.parse(raw); } catch { return; }

    if (msg.type === 'join') {
      ws.room = msg.room;
      ws.playerId = msg.playerId;
      ws.nickname = msg.nickname || `Player_${msg.playerId?.slice(0, 4)}`;
      ws.isAdmin = msg.isAdmin || false;

      if (!rooms[ws.room]) rooms[ws.room] = new Set();
      rooms[ws.room].add(ws);
      if (ws.playerId) playerWsMap[ws.playerId] = ws;

      // Tell THIS player they are admitted so the game screen shows
      ws.send(JSON.stringify({ type: 'admitted' }));

      broadcast(ws.room, { type: 'system', content: `${ws.nickname} joined the room.` }, null);
      broadcastCount(ws.room);
    }

    if (msg.type === 'chat' && ws.room) {
      const player = db.get('players').find({ id: ws.playerId }).value();
      if (player?.muteUntil && player.muteUntil > Date.now()) {
        ws.send(JSON.stringify({ type: 'error', content: `You are muted until ${new Date(player.muteUntil).toLocaleTimeString()}` }));
        return;
      }

      const content = String(msg.content || '').trim().slice(0, 300);
      if (!content) return;
      const msgId = uuidv4();
      const message = { id: msgId, room: ws.room, playerId: ws.playerId, nickname: ws.nickname, content, ts: Date.now() };
      db.get('messages').push(message).write();
      broadcast(ws.room, { type: 'chat', id: msgId, nickname: ws.nickname, content, playerId: ws.playerId, ts: Date.now() }, null);
    }

    if (msg.type === 'score_update' && ws.room) {
      broadcast(ws.room, { type: 'score_update', nickname: ws.nickname, score: msg.score }, ws);
    }

    // Admin: take control / spectate relay
    if (msg.type === 'admin_input' && ws.isAdmin) {
      const target = playerWsMap[msg.targetPlayerId];
      if (target && target.readyState === WebSocket.OPEN) {
        target.send(JSON.stringify({ type: 'admin_control', input: msg.input }));
      }
    }

    // Game state relay for spectating
    if (msg.type === 'game_state') {
      // Relay to any admin watching this player
      Object.values(playerWsMap).forEach(adminWs => {
        if (adminWs.isAdmin && adminWs.spectating === ws.playerId && adminWs.readyState === WebSocket.OPEN) {
          adminWs.send(JSON.stringify({ type: 'spectate_state', playerId: ws.playerId, state: msg.state }));
        }
      });
    }

    if (msg.type === 'admin_spectate' && ws.isAdmin) {
      ws.spectating = msg.targetPlayerId;
    }
  });

  ws.on('close', () => {
    if (ws.playerId && playerWsMap[ws.playerId] === ws) delete playerWsMap[ws.playerId];
    if (ws.room && rooms[ws.room]) {
      rooms[ws.room].delete(ws);
      broadcast(ws.room, { type: 'system', content: `${ws.nickname} left the room.` }, null);
      broadcastCount(ws.room);
    }
  });
});

function broadcast(room, data, excludeWs) {
  if (!rooms[room]) return;
  const payload = JSON.stringify(data);
  rooms[room].forEach(c => { if (c !== excludeWs && c.readyState === WebSocket.OPEN) c.send(payload); });
}

function broadcastToAll(data) {
  const payload = JSON.stringify(data);
  wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(payload); });
}

function broadcastCount(room) {
  broadcast(room, { type: 'online_count', count: rooms[room]?.size || 0 }, null);
}

function sendToPlayer(playerId, data) {
  const ws = playerWsMap[playerId];
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
}

function kickPlayer(playerId, reason) {
  const ws = playerWsMap[playerId];
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'kicked', reason }));
    ws.close();
  }
}

// ── Join private room via link ─────────────────────────────────────────────────
app.get('/join/:code', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Route /cron
app.get('/cron', (req, res) => {
    console.log('Cron exécuté à', new Date());

    // 👉 Mets ici ton code à exécuter
    // Exemple :
    // - nettoyer une base de données
    // - appeler une API
    // - envoyer des emails

    res.status(200).send('Cron exécuté');
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🎮 SAME GAME → http://localhost:${PORT}`));
