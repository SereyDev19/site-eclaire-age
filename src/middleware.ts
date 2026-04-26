import { defineMiddleware } from 'astro:middleware';

const USERNAME = 'chhims';
const PASSWORD = 'Lesquatrechiens1!';
const COOKIE_NAME = 'ea_auth';
const COOKIE_SECRET = 'eclairage_auth_ok_2026';

export const onRequest = defineMiddleware(async (context, next) => {
  const { request, cookies } = context;

  // Already authenticated via cookie
  if (cookies.get(COOKIE_NAME)?.value === COOKIE_SECRET) {
    return next();
  }

  // Handle login form submission
  if (request.method === 'POST') {
    const form = await request.formData();
    const user = form.get('username')?.toString().trim();
    const pass = form.get('password')?.toString();

    if (user === USERNAME && pass === PASSWORD) {
      const url = new URL(request.url);
      const res = new Response(null, {
        status: 302,
        headers: { 'Location': url.pathname },
      });
      res.headers.append(
        'Set-Cookie',
        `${COOKIE_NAME}=${COOKIE_SECRET}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`
      );
      return res;
    }

    return new Response(loginHtml(true), {
      status: 401,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  return new Response(loginHtml(false), {
    status: 401,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
});

function loginHtml(error: boolean): string {
  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Connexion — Éclaire'Âge</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      min-height: 100dvh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg, #2c1c3c 0%, #7a28b8 100%);
      padding: 24px;
    }
    .card {
      background: #fff;
      border-radius: 24px;
      padding: 48px 40px;
      width: 100%;
      max-width: 420px;
      box-shadow: 0 32px 80px rgba(44,20,60,0.40);
    }
    .header { text-align: center; margin-bottom: 36px; }
    .header h1 { font-size: 26px; font-weight: 800; color: #7a28b8; letter-spacing: -.02em; }
    .header p { font-size: 14px; color: #999; margin-top: 6px; }
    .error {
      background: #fff0f0; border: 1px solid #fcc; color: #c00;
      padding: 10px 14px; border-radius: 10px; font-size: 13px; margin-bottom: 20px;
    }
    label { display: block; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .09em; color: #444; margin-bottom: 6px; }
    input {
      width: 100%; padding: 13px 16px;
      border: 1.5px solid #e2d5f0; border-radius: 12px;
      font-size: 15px; outline: none; transition: border-color .2s;
      margin-bottom: 18px; color: #222;
    }
    input:focus { border-color: #7a28b8; box-shadow: 0 0 0 3px rgba(122,40,184,.12); }
    button {
      width: 100%; padding: 14px;
      background: #7a28b8; color: #fff;
      border: none; border-radius: 999px;
      font-size: 15px; font-weight: 700; cursor: pointer;
      transition: background .2s, transform .15s;
      margin-top: 4px;
    }
    button:hover { background: #6020a0; transform: translateY(-1px); }
    button:active { transform: none; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <h1>Éclaire'Âge</h1>
      <p>Espace réservé — veuillez vous identifier</p>
    </div>
    ${error ? '<div class="error">Identifiants incorrects. Réessayez.</div>' : ''}
    <form method="POST">
      <label for="username">Identifiant</label>
      <input id="username" type="text" name="username" autocomplete="username" required autofocus/>
      <label for="password">Mot de passe</label>
      <input id="password" type="password" name="password" autocomplete="current-password" required/>
      <button type="submit">Se connecter</button>
    </form>
  </div>
</body>
</html>`;
}
