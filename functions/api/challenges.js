async function parseAndAuthenticate(request, SECRET) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  try {
    const token = authHeader.split(' ')[1];
    const [b64Payload, sigHex] = token.split('.');
    const payload = atob(b64Payload);
    const [username, expires, role] = payload.split('|');
    if (Date.now() > parseInt(expires)) return null;
    return { username, role: role || 'member' };
  } catch { return null; }
}

export async function onRequest(context) {
  const { env, request } = context;
  const SECRET = env.JWT_SECRET || "fallback_gammath_crypto_key_2026";
  const userClaim = await parseAndAuthenticate(request, SECRET);
  
  if (!userClaim) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
  const method = request.method;

  // Enforce table structures dynamically if operating inside D1
  if (env.DB) {
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS weekly_challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT, description TEXT, topic TEXT, difficulty TEXT,
        attached_file TEXT, is_active INTEGER DEFAULT 1, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `).run();
  }

  if (method === "GET") {
    if (env.DB) {
      const { results } = await env.DB.prepare("SELECT * FROM weekly_challenges ORDER BY id DESC").all();
      return new Response(JSON.stringify(results), { headers: { "Content-Type": "application/json" } });
    }
    // Shared runtime global mock state fallback if D1 isn't coupled
    return new Response(JSON.stringify([
      { id: 1, title: "Riemann Hypothesis Base Lemma", description: "Prove non-trivial zeros lie on the critical path line.", topic: "Analytic Number Theory", difficulty: "Olympiad", is_active: 1 }
    ]), { headers: { "Content-Type": "application/json" } });
  }

  if (method === "POST" || method === "PUT") {
    if (userClaim.role !== "admin") return new Response(JSON.stringify({ error: "Forbidden: Admin access required" }), { status: 403 });
    const body = await request.json();

    if (method === "POST") {
      if (env.DB) {
        await env.DB.prepare("INSERT INTO weekly_challenges (title, description, topic, difficulty, attached_file, is_active) VALUES (?, ?, ?, ?, ?, 1)")
          .bind(body.title, body.description, body.topic, body.difficulty, body.attached_file || "").run();
      }
      return new Response(JSON.stringify({ success: true, message: "Challenge deployed successfully." }), { headers: { "Content-Type": "application/json" } });
    }

    if (method === "PUT") {
      if (env.DB) {
        await env.DB.prepare("UPDATE weekly_challenges SET title=?, description=?, topic=?, difficulty=?, is_active=? WHERE id=?")
          .bind(body.title, body.description, body.topic, body.difficulty, body.is_active, body.id).run();
      }
      return new Response(JSON.stringify({ success: true, message: "Challenge metrics synchronized." }), { headers: { "Content-Type": "application/json" } });
    }
  }

  return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 451 });
}