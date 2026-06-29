async function authenticate(request, SECRET) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.split(' ')[1];
  try {
    const [b64Payload, sigHex] = token.split('.');
    const payload = atob(b64Payload);
    const [username] = payload.split('|');
    const encoder = new TextEncoder();
    const cryptoKey = await crypto.subtle.importKey('raw', encoder.encode(SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(payload));
    const expectedSigHex = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
    return expectedSigHex === sigHex ? username : null;
  } catch { return null; }
}

// GET: 获取最新的 50 条公屏聊天记录
export async function onRequestGet(context) {
  const { env, request } = context;
  const SECRET = env.JWT_SECRET || "fallback_gammath_crypto_key_2026";
  const username = await authenticate(request, SECRET);
  if (!username) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });

  const { results } = await env.DB.prepare(
    "SELECT username, message, timestamp FROM chat_messages ORDER BY id DESC LIMIT 50"
  ).all();

  // 反转排序，使时间线正向显示
  return new Response(JSON.stringify(results.reverse()), {
    headers: { "Content-Type": "application/json" }
  });
}

// POST: 发送并保存一条聊天消息
export async function onRequestPost(context) {
  const { env, request } = context;
  const SECRET = env.JWT_SECRET || "fallback_gammath_crypto_key_2026";
  const username = await authenticate(request, SECRET);
  if (!username) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });

  const { message } = await request.json();
  if (!message || message.trim() === "") {
    return new Response(JSON.stringify({ error: "Empty string" }), { status: 400 });
  }

  const user = await env.DB.prepare("SELECT id, username FROM users WHERE username = ?").bind(username).first();

  await env.DB.prepare("INSERT INTO chat_messages (user_id, username, message) VALUES (?, ?, ?)")
    .bind(user.id, user.username, message.trim())
    .run();

  return new Response(JSON.stringify({ success: true }), {
    headers: { "Content-Type": "application/json" }
  });
}
