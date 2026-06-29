export async function onRequestPost(context) {
  const { env, request } = context;
  const SECRET = env.JWT_SECRET || "fallback_gammath_crypto_key_2026";

  try {
    const { username, password } = await request.json();
    const normalizedUser = username.trim().toLowerCase();

    // 计算传入密码的哈希结果
    const msgBuffer = new TextEncoder().encode(password + "GammathSalt2026");
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const inputHash = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

    // 从数据库比对
    const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?")
      .bind(normalizedUser)
      .first();

    if (!user || user.password_hash !== inputHash) {
      return new Response(JSON.stringify({ error: "Invalid username or password" }), { status: 401 });
    }

    // 签发无状态签名安全 Token 授权令牌
    const expires = Date.now() + 86400000 * 7; // 7天免登时效
    const payload = `${normalizedUser}|${expires}`;
    
    const encoder = new TextEncoder();
    const cryptoKey = await crypto.subtle.importKey('raw', encoder.encode(SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(payload));
    const sigHex = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
    
    const finalToken = btoa(payload) + '.' + sigHex;

    return new Response(JSON.stringify({ success: true, token: finalToken, username: user.username }), {
      headers: { "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}
