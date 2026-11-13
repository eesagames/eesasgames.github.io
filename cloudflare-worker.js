const ALLOWED_ORIGINS = new Set([
  "https://eesagames.github.io",
  "https://eesagames.qd.je"
]);
const DAY = 86400;
const CHAT_MAX = 1000;
const MAX_JSON = 16000;
let schemaReady;

function headers(origin) {
  return {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": origin || "https://eesagames.github.io",
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization"
  };
}
function reply(data, status = 200, origin) {
  return new Response(JSON.stringify(data), { status, headers: headers(origin) });
}
function fail(message, status = 400, origin) { return reply({ error: message }, status, origin); }
function now() { return Math.floor(Date.now() / 1000); }
async function hash(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
}
function equal(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}
function randomToken() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, "0")).join("");
}
async function init(env) {
  if (!schemaReady) schemaReady = (async () => {
    const statements = [
      "CREATE TABLE IF NOT EXISTS eg_account_data (account_id INTEGER PRIMARY KEY, profile_json TEXT NOT NULL DEFAULT '{}', updated_at INTEGER NOT NULL)",
      "CREATE TABLE IF NOT EXISTS eg_settings (account_id INTEGER PRIMARY KEY, settings_json TEXT NOT NULL DEFAULT '{}', updated_at INTEGER NOT NULL)",
      "CREATE TABLE IF NOT EXISTS eg_extensions (account_id INTEGER PRIMARY KEY, extension_id TEXT NOT NULL DEFAULT 'classic', updated_at INTEGER NOT NULL)",
      "CREATE TABLE IF NOT EXISTS eg_game_history (id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER NOT NULL, game_id TEXT NOT NULL, game_title TEXT NOT NULL, played_at INTEGER NOT NULL)",
      "CREATE INDEX IF NOT EXISTS eg_game_history_account_date ON eg_game_history(account_id, played_at DESC)",
      "CREATE TABLE IF NOT EXISTS eg_chat_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER NOT NULL, username TEXT NOT NULL, message TEXT NOT NULL, created_at INTEGER NOT NULL)",
      "CREATE INDEX IF NOT EXISTS eg_chat_date ON eg_chat_messages(id DESC)",
      "CREATE TABLE IF NOT EXISTS eg_presence (account_id INTEGER PRIMARY KEY, session_hash TEXT NOT NULL, activity TEXT NOT NULL DEFAULT 'Browsing', visibility INTEGER NOT NULL DEFAULT 1, last_seen INTEGER NOT NULL)",
      "CREATE INDEX IF NOT EXISTS eg_presence_seen ON eg_presence(last_seen DESC)",
      "CREATE TABLE IF NOT EXISTS eg_bans (account_id INTEGER PRIMARY KEY, actor_id INTEGER NOT NULL, reason TEXT NOT NULL DEFAULT '', expires_at INTEGER, created_at INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1)"
    ];
    for (const sql of statements) await env.DB.prepare(sql).run();
  })();
  return schemaReady;
}
async function authenticate(request, env) {
  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Bearer ")) return null;
  const token = header.slice(7);
  if (!token || token.length > 256) return null;
  const tokenHash = await hash(token);
  const account = await env.DB.prepare(
    "SELECT a.id, a.username, a.tier, a.power_rank, a.is_banned FROM access_sessions s JOIN access_accounts a ON a.id=s.account_id WHERE s.token_hash=? AND s.expires_at>?"
  ).bind(tokenHash, now()).first();
  if (!account) return null;
  const ban = await env.DB.prepare("SELECT expires_at FROM eg_bans WHERE account_id=? AND active=1").bind(account.id).first();
  if (ban && ban.expires_at !== null && Number(ban.expires_at) <= now()) {
    await env.DB.prepare("UPDATE eg_bans SET active=0 WHERE account_id=?").bind(account.id).run();
    await env.DB.prepare("UPDATE access_accounts SET is_banned=0 WHERE id=?").bind(account.id).run();
  } else if (ban || account.is_banned) {
    return null;
  }
  return { ...account, tokenHash };
}
async function bodyJson(request) {
  const text = await request.text();
  if (text.length > MAX_JSON) throw new Error("Request too large");
  return JSON.parse(text || "{}");
}
function validObject(value) { return value && typeof value === "object" && !Array.isArray(value); }
async function saveJson(env, table, accountId, value) {
  if (!validObject(value)) throw new Error("Expected an object");
  const json = JSON.stringify(value);
  if (json.length > MAX_JSON) throw new Error("Data too large");
  const column = table === "eg_settings" ? "settings_json" : "profile_json";
  await env.DB.prepare("INSERT INTO " + table + " (account_id, " + column + ", updated_at) VALUES (?, ?, ?) ON CONFLICT(account_id) DO UPDATE SET " + column + "=excluded." + column + ", updated_at=excluded.updated_at")
    .bind(accountId, json, now()).run();
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin");
    if (origin && !ALLOWED_ORIGINS.has(origin)) return fail("Origin not allowed", 403, "https://eesagames.github.io");
    const corsOrigin = origin || "https://eesagames.github.io";
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: headers(corsOrigin) });
    try {
      await init(env);
      const path = url.pathname;
      if (path === "/api/health" && request.method === "GET") return reply({ status: "online", project: "EesaGames", version: "3.0" }, 200, corsOrigin);
      if (path === "/api/db-check" && request.method === "GET") {
        await env.DB.prepare("SELECT 1").first();
        return reply({ status: "connected" }, 200, corsOrigin);
      }

      if (path === "/api/login" && request.method === "POST") {
        const ip = request.headers.get("CF-Connecting-IP") || "unknown";
        const key = "login:" + ip;
        const attempts = Number(await env.CACHE.get(key) || 0);
        if (attempts >= 10) return fail("Too many attempts. Try again later.", 429, corsOrigin);
        const body = await bodyJson(request);
        const code = body.code;
        if (typeof code !== "string" || code.length < 8 || code.length > 256) {
          await env.CACHE.put(key, String(attempts + 1), { expirationTtl: 600 });
          return fail("Invalid access code", 401, corsOrigin);
        }
        if (!env.ACCESS_CODES) return fail("Authentication not configured", 503, corsOrigin);
        let codes;
        try { codes = JSON.parse(env.ACCESS_CODES); } catch { return fail("Authentication configuration error", 503, corsOrigin); }
        let username = null;
        for (const [name, storedCode] of Object.entries(codes)) if (equal(code, storedCode)) { username = name; break; }
        if (!username) {
          await env.CACHE.put(key, String(attempts + 1), { expirationTtl: 600 });
          return fail("Invalid access code", 401, corsOrigin);
        }
        const account = await env.DB.prepare("SELECT id, username, tier, power_rank, is_banned FROM access_accounts WHERE username=?").bind(username).first();
        if (!account) return fail("Account not configured", 403, corsOrigin);
        const ban = await env.DB.prepare("SELECT expires_at FROM eg_bans WHERE account_id=? AND active=1").bind(account.id).first();
        if (ban && ban.expires_at !== null && Number(ban.expires_at) <= now()) {
          await env.DB.prepare("UPDATE eg_bans SET active=0 WHERE account_id=?").bind(account.id).run();
          await env.DB.prepare("UPDATE access_accounts SET is_banned=0 WHERE id=?").bind(account.id).run();
        } else if (ban || account.is_banned) return fail("This account is banned", 403, corsOrigin);
        const token = randomToken();
        const expires = now() + 30 * DAY;
        await env.DB.prepare("INSERT INTO access_sessions (account_id, token_hash, expires_at) VALUES (?, ?, ?)")
          .bind(account.id, await hash(token), expires).run();
        await env.CACHE.delete(key);
        return reply({ success: true, token, expires, account: { username: account.username, tier: account.tier, power_rank: account.power_rank } }, 200, corsOrigin);
      }

      if (path === "/api/me" && request.method === "GET") {
        const account = await authenticate(request, env);
        if (!account) return fail("Unauthorised", 401, corsOrigin);
        return reply({ authenticated: true, account: { username: account.username, tier: account.tier, power_rank: account.power_rank } }, 200, corsOrigin);
      }
      if (path === "/api/logout" && request.method === "POST") {
        const account = await authenticate(request, env);
        if (account) {
          await env.DB.prepare("DELETE FROM access_sessions WHERE token_hash=?").bind(account.tokenHash).run();
          await env.DB.prepare("DELETE FROM eg_presence WHERE account_id=?").bind(account.id).run();
        }
        return reply({ success: true }, 200, corsOrigin);
      }

      const account = await authenticate(request, env);
      if (!account) return fail("Unauthorised", 401, corsOrigin);

      if (path === "/api/account" && request.method === "GET") {
        const row = await env.DB.prepare("SELECT profile_json, updated_at FROM eg_account_data WHERE account_id=?").bind(account.id).first();
        return reply({ account: { username: account.username, tier: account.tier, power_rank: account.power_rank }, profile: row ? JSON.parse(row.profile_json) : {}, updated_at: row?.updated_at || null }, 200, corsOrigin);
      }
      if (path === "/api/account" && request.method === "PUT") {
        const body = await bodyJson(request);
        await saveJson(env, "eg_account_data", account.id, body.profile);
        return reply({ success: true }, 200, corsOrigin);
      }
      if (path === "/api/settings" && request.method === "GET") {
        const row = await env.DB.prepare("SELECT settings_json, updated_at FROM eg_settings WHERE account_id=?").bind(account.id).first();
        return reply({ settings: row ? JSON.parse(row.settings_json) : {}, updated_at: row?.updated_at || null }, 200, corsOrigin);
      }
      if (path === "/api/settings" && request.method === "PUT") {
        const body = await bodyJson(request);
        await saveJson(env, "eg_settings", account.id, body.settings);
        return reply({ success: true }, 200, corsOrigin);
      }
      if (path === "/api/extensions" && request.method === "GET") {
        const row = await env.DB.prepare("SELECT extension_id, updated_at FROM eg_extensions WHERE account_id=?").bind(account.id).first();
        return reply({ extension: row?.extension_id || "classic", updated_at: row?.updated_at || null }, 200, corsOrigin);
      }
      if (path === "/api/extensions" && request.method === "PUT") {
        const body = await bodyJson(request);
        const allowed = new Set(["classic", "felixt", "pitch", "midnight", "apple"]);
        if (!allowed.has(body.extension)) return fail("Unknown extension", 400, corsOrigin);
        await env.DB.prepare("INSERT INTO eg_extensions (account_id, extension_id, updated_at) VALUES (?, ?, ?) ON CONFLICT(account_id) DO UPDATE SET extension_id=excluded.extension_id, updated_at=excluded.updated_at")
          .bind(account.id, body.extension, now()).run();
        return reply({ success: true, extension: body.extension }, 200, corsOrigin);
      }
      if (path === "/api/games/history" && request.method === "GET") {
        const limit = Math.min(50, Math.max(1, Number(url.searchParams.get("limit")) || 20));
        const rows = await env.DB.prepare("SELECT id, game_id, game_title, played_at FROM eg_game_history WHERE account_id=? ORDER BY played_at DESC LIMIT ?").bind(account.id, limit).all();
        return reply({ history: rows.results || [] }, 200, corsOrigin);
      }
      if (path === "/api/games/history" && request.method === "POST") {
        const body = await bodyJson(request);
        if (typeof body.game_id !== "string" || !body.game_id || body.game_id.length > 120 || typeof body.game_title !== "string" || !body.game_title.trim() || body.game_title.length > 160)
          return fail("Invalid game details", 400, corsOrigin);
        await env.DB.prepare("INSERT INTO eg_game_history (account_id, game_id, game_title, played_at) VALUES (?, ?, ?, ?)")
          .bind(account.id, body.game_id, body.game_title.trim(), now()).run();
        return reply({ success: true }, 201, corsOrigin);
      }
      if (path === "/api/chat/messages" && request.method === "GET") {
        const before = Math.max(0, Number(url.searchParams.get("before")) || 0);
        const limit = Math.min(100, Math.max(1, Number(url.searchParams.get("limit")) || 50));
        const rows = before
          ? await env.DB.prepare("SELECT id, username, message, created_at FROM eg_chat_messages WHERE id<? ORDER BY id DESC LIMIT ?").bind(before, limit).all()
          : await env.DB.prepare("SELECT id, username, message, created_at FROM eg_chat_messages ORDER BY id DESC LIMIT ?").bind(limit).all();
        return reply({ messages: (rows.results || []).reverse() }, 200, corsOrigin);
      }
      if (path === "/api/chat/messages" && request.method === "POST") {
        const body = await bodyJson(request);
        const message = typeof body.message === "string" ? body.message.trim() : "";
        if (!message || message.length > CHAT_MAX) return fail("Message must be 1–1000 characters", 400, corsOrigin);
        const result = await env.DB.prepare("INSERT INTO eg_chat_messages (account_id, username, message, created_at) VALUES (?, ?, ?, ?)")
          .bind(account.id, account.username, message, now()).run();
        return reply({ success: true, id: result.meta?.last_row_id || null }, 201, corsOrigin);
      }
      if (path === "/api/presence/heartbeat" && request.method === "POST") {
        const body = await bodyJson(request);
        const activity = typeof body.activity === "string" ? body.activity.slice(0, 60) : "Browsing";
        const visibility = body.visibility === false ? 0 : 1;
        await env.DB.prepare("INSERT INTO eg_presence (account_id, session_hash, activity, visibility, last_seen) VALUES (?, ?, ?, ?, ?) ON CONFLICT(account_id) DO UPDATE SET session_hash=excluded.session_hash, activity=excluded.activity, visibility=excluded.visibility, last_seen=excluded.last_seen")
          .bind(account.id, account.tokenHash, activity, visibility, now()).run();
        return reply({ success: true }, 200, corsOrigin);
      }
      if (path === "/api/presence" && request.method === "GET") {
        const rows = await env.DB.prepare("SELECT a.username, a.tier, p.activity, p.last_seen FROM eg_presence p JOIN access_accounts a ON a.id=p.account_id WHERE p.visibility=1 AND p.last_seen>? ORDER BY p.last_seen DESC LIMIT 100")
          .bind(now() - 45).all();
        return reply({ online: rows.results || [] }, 200, corsOrigin);
      }

      if ((path === "/api/moderation/ban" || path === "/api/moderation/unban") && request.method === "POST") {
        const body = await bodyJson(request);
        if (typeof body.username !== "string" || !body.username.trim()) return fail("Username required", 400, corsOrigin);
        const target = await env.DB.prepare("SELECT id, username, power_rank FROM access_accounts WHERE username=?").bind(body.username.trim()).first();
        if (!target) return fail("Account not found", 404, corsOrigin);
        if (Number(target.power_rank) >= 100 || Number(account.power_rank) <= Number(target.power_rank)) return fail("Insufficient authority", 403, corsOrigin);
        const banning = path.endsWith("/ban");
        if (banning) {
          const duration = body.duration_seconds == null ? null : Number(body.duration_seconds);
          const allowedDurations = new Set([300, 3600, 86400, 604800, 2592000]);
          if (duration !== null && !allowedDurations.has(duration)) return fail("Invalid ban duration", 400, corsOrigin);
          const reason = typeof body.reason === "string" ? body.reason.trim().slice(0, 300) : "";
          const expires = duration === null ? null : now() + duration;
          await env.DB.prepare("INSERT INTO eg_bans (account_id, actor_id, reason, expires_at, created_at, active) VALUES (?, ?, ?, ?, ?, 1) ON CONFLICT(account_id) DO UPDATE SET actor_id=excluded.actor_id, reason=excluded.reason, expires_at=excluded.expires_at, created_at=excluded.created_at, active=1")
            .bind(target.id, account.id, reason, expires, now()).run();
          await env.DB.prepare("UPDATE access_accounts SET is_banned=1 WHERE id=?").bind(target.id).run();
          await env.DB.prepare("DELETE FROM access_sessions WHERE account_id=?").bind(target.id).run();
          await env.DB.prepare("DELETE FROM eg_presence WHERE account_id=?").bind(target.id).run();
        } else {
          await env.DB.prepare("UPDATE eg_bans SET active=0 WHERE account_id=?").bind(target.id).run();
          await env.DB.prepare("UPDATE access_accounts SET is_banned=0 WHERE id=?").bind(target.id).run();
        }
        await env.DB.prepare("INSERT INTO moderation_logs (actor_id, target_id, action) VALUES (?, ?, ?)")
          .bind(account.id, target.id, banning ? "BAN" : "UNBAN").run();
        return reply({ success: true, action: banning ? "banned" : "unbanned", target: target.username }, 200, corsOrigin);
      }
      return fail("Endpoint not found", 404, corsOrigin);
    } catch (error) {
      return fail(error?.message === "Request too large" ? error.message : "Internal server error", error?.message === "Request too large" ? 413 : 500, request.headers.get("Origin") || "https://eesagames.github.io");
    }
  }
};