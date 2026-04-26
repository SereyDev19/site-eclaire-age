import { defineMiddleware } from 'astro:middleware';

const USERNAME = 'chhims';
const PASSWORD = 'Lesquatrechiens1!';

export const onRequest = defineMiddleware((context, next) => {
  const authHeader = context.request.headers.get('authorization');

  if (authHeader?.startsWith('Basic ')) {
    const encoded = authHeader.slice(6);
    const decoded = atob(encoded);
    const colon = decoded.indexOf(':');
    const user = decoded.slice(0, colon);
    const pass = decoded.slice(colon + 1);

    if (user === USERNAME && pass === PASSWORD) {
      return next();
    }
  }

  return new Response('Accès non autorisé', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="Accès restreint", charset="UTF-8"',
    },
  });
});
