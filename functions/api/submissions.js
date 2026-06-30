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

  if (env.DB) {
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS challenge_submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, challenge_id INTEGER, student_name TEXT,
        explanation TEXT, attachment_payload TEXT, status TEXT DEFAULT 'Pending', feedback TEXT DEFAULT ''
      )
    `).run();
  }

  if (method === "GET") {
    if (env.DB) {
      let query = "SELECT * FROM challenge_submissions ORDER BY id DESC";
      if (userClaim.role !== 'admin') {
        query = `SELECT * FROM challenge_submissions WHERE student_name = '${userClaim.username}' ORDER BY id DESC`;
      }
      const { results } = await env.DB.prepare(query).all();
      return new Response(JSON.stringify(results), { headers: { "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify([]), { headers: { "Content-Type": "application/json" } });
  }

  if (method === "POST") {
    const body = await request.json();
    if (env.DB) {
      await env.DB.prepare("INSERT INTO challenge_submissions (challenge_id, student_name, explanation, attachment_payload) VALUES (?, ?, ?, ?)")
        .bind(body.challenge_id, userClaim.username, body.explanation, JSON.stringify(body.images || [])).run();
    }
    return new Response(JSON.stringify({ success: true, message: "Solution pipeline synchronized." }), { headers: { "Content-Type": "application/json" } });
  }

  if (method === "PUT") {
    if (userClaim.role !== 'admin') return new Response(JSON.stringify({ error: "Forbidden" }), { status: 403 });
    const body = await request.json();
    if (env.DB) {
      await env.DB.prepare("UPDATE challenge_submissions SET status=?, feedback=? WHERE id=?")
        .bind(body.status, body.feedback, body.id).run();
    }
    return new Response(JSON.stringify({ success: true, message: "Grading record submitted successfully." }), { headers: { "Content-Type": "application/json" } });
  }

  return new Response(JSON.stringify({ error: "Method structural mismatch" }), { status: 405 });
}