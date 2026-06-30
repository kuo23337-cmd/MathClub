export async function onRequestPost(context) {
  const { env, request } = context;
  const SECRET = env.JWT_SECRET || "fallback_gammath_crypto_key_2026";

  try {
    const { id_token, fullName } = await request.json();
    if (!id_token) return new Response(JSON.stringify({ error: "Missing identity token" }), { status: 400 });

    // Validate identity signature securely with Google Tokeninfo infrastructure
    const googleRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${id_token}`);
    if (!googleRes.ok) return new Response(JSON.stringify({ error: "Invalid identity credentials" }), { status: 401 });
    
    const payload = await googleRes.json();
    const email = payload.email || "";
    const googleSub = payload.sub;

    // Feature 7: Match administrator access rights securely
    const assignedRole = (email.trim().toLowerCase() === 'kuo23337@gmail.com') ? 'admin' : 'member';
    const dbLookupKey = `google:${googleSub}`;
    const cleanedName = fullName ? fullName.trim() : (payload.name || "Math Club Member");

    let finalUsername = cleanedName;

    // Database Operation with automated schema safety fallbacks
    if (env.DB) {
      try {
        // Feature 6: Ensure target tables exist natively
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            username TEXT UNIQUE, 
            password_hash TEXT, 
            role TEXT DEFAULT 'member'
          )
        `).run();

        const user = await env.DB.prepare("SELECT * FROM users WHERE password_hash = ?").bind(dbLookupKey).first();
        if (user) {
          await env.DB.prepare("UPDATE users SET role = ? WHERE id = ?").bind(assignedRole, user.id).run();
          finalUsername = user.username;
        } else {
          const nameCheck = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(cleanedName).first();
          if (nameCheck) {
            finalUsername = `${cleanedName}#${Math.floor(1000 + Math.random() * 9000)}`;
          }
          await env.DB.prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)")
            .bind(finalUsername, dbLookupKey, assignedRole)
            .run();
        }
      } catch (dbError) {
        console.error("D1 transaction bypassed, shifting to stateless fallback engine.", dbError);
      }
    }

    // Sign cross-compatible JWT containing standard elements (username|expires|role)
    const expires = Date.now() + 86400000 * 7; 
    const tokenPayload = `${finalUsername}|${expires}|${assignedRole}`;
    
    const encoder = new TextEncoder();
    const cryptoKey = await crypto.subtle.importKey('raw', encoder.encode(SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(tokenPayload));
    const sigHex = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
    const appToken = btoa(tokenPayload) + '.' + sigHex;

    return new Response(JSON.stringify({ 
      success: true, 
      token: appToken, 
      username: finalUsername, 
      role: assignedRole 
    }), { headers: { "Content-Type": "application/json" } });

  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}
