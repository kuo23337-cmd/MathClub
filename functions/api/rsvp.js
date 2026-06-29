// 通用 Token 鉴权中间件
async function authenticate(request, SECRET) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.split(' ')[1];
  try {
    const [b64Payload, sigHex] = token.split('.');
    const payload = atob(b64Payload);
    const [username, expires] = payload.split('|');
    if (Date.now() > parseInt(expires)) return null;

    const encoder = new TextEncoder();
    const cryptoKey = await crypto.subtle.importKey('raw', encoder.encode(SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(payload));
    const expectedSigHex = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');

    return expectedSigHex === sigHex ? username : null;
  } catch { return null; }
}

// GET: 获取当前登录用户的预约列表
export async function onRequestGet(context) {
  const { env, request } = context;
  const SECRET = env.JWT_SECRET || "fallback_gammath_crypto_key_2026";
  const username = await authenticate(request, SECRET);
  if (!username) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });

  const user = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
  const rows = await env.DB.prepare("SELECT seminar_id FROM rsvps WHERE user_id = ?").bind(user.id).all();
  
  const rsvps = rows.results.map(r => r.seminar_id);
  return new Response(JSON.stringify({ rsvps }), { headers: { "Content-Type": "application/json" } });
}

// POST: 切换预约状态（预约/取消预约）
export async function onRequestPost(context) {
  const { env, request } = context;
  const SECRET = env.JWT_SECRET || "fallback_gammath_crypto_key_2026";
  const username = await authenticate(request, SECRET);
  if (!username) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });

  const { seminarId } = await request.json();
  const user = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();

  // 检查是否已经预约过
  const existing = await env.DB.prepare("SELECT id FROM rsvps WHERE user_id = ? AND seminar_id = ?")
    .bind(user.id, seminarId)
    .first();

  if (existing) {
    // 已预约则取消预约
    await env.DB.prepare("DELETE FROM rsvps WHERE user_id = ? AND seminar_id = ?").bind(user.id, seminarId).run();
  } else {
    // 未预约则增加预约
    await env.DB.prepare("INSERT INTO rsvps (user_id, seminar_id) VALUES (?, ?)").bind(user.id, seminarId).run();
  }

  return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
}
