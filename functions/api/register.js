export async function onRequestPost(context) {
  const { env, request } = context;
  
  try {
    const { username, password } = await request.json();
    if (!username || !password) {
      return new Response(JSON.stringify({ error: "Missing fields" }), { status: 400 });
    }

    const normalizedUser = username.trim().toLowerCase();

    // 检查用户是否已被占用
    const existingUser = await env.DB.prepare("SELECT id FROM users WHERE username = ?")
      .bind(normalizedUser)
      .first();

    if (existingUser) {
      return new Response(JSON.stringify({ error: "Username already exists" }), { status: 409 });
    }

    // 利用原生 Web Crypto API 实现高强度密码哈希存储
    const msgBuffer = new TextEncoder().encode(password + "GammathSalt2026");
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashHex = Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    // 存入 D1 数据库
    await env.DB.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
      .bind(normalizedUser, hashHex)
      .run();

    return new Response(JSON.stringify({ success: true }), {
      headers: { "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}
