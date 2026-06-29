export async function onRequestPost(context) {
  const { env, request } = context;
  const SECRET = env.JWT_SECRET || "fallback_gammath_crypto_key_2026";

  try {
    const { id_token, fullName } = await request.json();
    if (!id_token) {
      return new Response(JSON.stringify({ error: "Missing token token" }), { status: 400 });
    }

    // 1. 安全联机向 Google OAuth 服务器交叉验证此 Token 的不可伪造性
    const googleRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${id_token}`);
    if (!googleRes.ok) {
      return new Response(JSON.stringify({ error: "Invalid Google Identity Claim" }), { status: 401 });
    }
    const payload = await googleRes.json();
    const googleSub = payload.sub; // 用户的唯一谷歌账户编号

    const dbLookupKey = `google:${googleSub}`;

    // 2. 查看此谷歌账号此前是否在 D1 数据库中建立过映射
    const user = await env.DB.prepare("SELECT * FROM users WHERE password_hash = ?")
      .bind(dbLookupKey)
      .first();

    // 3. 情况 A：老用户直接登录，返回内部会话令牌
    if (user) {
      return await issueAppToken(user.username, SECRET);
    }

    // 4. 情况 B：新用户，且前端尚未提供真实姓名 -> 返回特殊控制指令，通知前端切入起名状态
    if (!fullName) {
      return new Response(JSON.stringify({ needName: true }), {
        headers: { "Content-Type": "application/json" }
      });
    }

    // 5. 情况 C：新用户提交了姓名，开始创建全栈用户档案
    const cleanedName = fullName.trim();
    if (cleanedName.length < 2) {
      return new Response(JSON.stringify({ error: "Name too short" }), { status: 400 });
    }

    // 查重：防止多名学生输入相同姓名产生冲突
    const nameCheck = await env.DB.prepare("SELECT id FROM users WHERE username = ?")
      .bind(cleanedName)
      .first();
    
    let finalUniqueName = cleanedName;
    if (nameCheck) {
      // 自动追加后缀区分同名同姓
      finalUniqueName = `${cleanedName}#${Math.floor(1000 + Math.random() * 9000)}`;
    }

    // 写入 D1
    await env.DB.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
      .bind(finalUniqueName, dbLookupKey)
      .run();

    return await issueAppToken(finalUniqueName, SECRET);

  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}

// 高阶无状态会话 JWT 签证封装
async function issueAppToken(username, secret) {
  const expires = Date.now() + 86400000 * 7; // 7 天有效期
  const tokenPayload = `${username}|${expires}`;
  
  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(tokenPayload));
  const sigHex = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
  
  const appToken = btoa(tokenPayload) + '.' + sigHex;

  return new Response(JSON.stringify({ success: true, token: appToken, username }), {
    headers: { "Content-Type": "application/json" }
  });
}
