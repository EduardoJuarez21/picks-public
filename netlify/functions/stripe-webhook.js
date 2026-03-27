const crypto = require('crypto');
const { Client } = require('pg');

function verifyStripeSignature(rawBody, sigHeader, secret) {
  try {
    const parts = {};
    sigHeader.split(',').forEach(p => {
      const idx = p.indexOf('=');
      parts[p.slice(0, idx)] = p.slice(idx + 1);
    });
    const t = parts['t'];
    const v1 = parts['v1'];
    if (!t || !v1) return false;
    const signedPayload = `${t}.${rawBody}`;
    const expected = crypto.createHmac('sha256', secret).update(signedPayload, 'utf8').digest('hex');
    return crypto.timingSafeEqual(Buffer.from(v1, 'hex'), Buffer.from(expected, 'hex'));
  } catch {
    return false;
  }
}

async function tgPost(token, method, body) {
  const res = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return res.json();
}

function getHeader(headers, name) {
  return headers[name] || headers[name.toLowerCase()] || '';
}

async function saveVipToDB(telegramId, telegramName) {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) return;
  const client = new Client({ connectionString: dbUrl, ssl: { rejectUnauthorized: false } });
  try {
    await client.connect();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await client.query(`
      INSERT INTO trial_users (user_id, username, first_name, expires_at, plan)
      VALUES ($1, $2, $3, $4, 'vip')
      ON CONFLICT (user_id) DO UPDATE
        SET expires_at  = EXCLUDED.expires_at,
            plan        = 'vip',
            removed_at  = NULL
    `, [telegramId, '', telegramName]);
  } finally {
    await client.end();
  }
}

exports.handler = async (event) => {
  const sig     = getHeader(event.headers, 'stripe-signature');
  const secret  = process.env.STRIPE_WEBHOOK_SECRET;
  const token   = process.env.TELEGRAM_BOT_TOKEN;
  const channel = process.env.TELEGRAM_CHAT_ID;
  const inbox   = process.env.TELEGRAM_INBOX_CHAT_ID;

  const rawBody = event.isBase64Encoded
    ? Buffer.from(event.body, 'base64').toString('utf8')
    : event.body;

  if (!secret || !verifyStripeSignature(rawBody, sig, secret)) {
    return { statusCode: 400, body: 'Invalid signature' };
  }

  let stripeEvent;
  try {
    stripeEvent = JSON.parse(rawBody);
  } catch {
    return { statusCode: 400, body: 'Invalid JSON' };
  }

  if (stripeEvent.type === 'checkout.session.completed') {
    const session      = stripeEvent.data.object;
    const telegramId   = session.metadata?.telegram_id;
    const telegramName = session.metadata?.telegram_name || '';

    if (telegramId && token && channel) {
      // Actualizar DB a plan VIP con 30 días
      await saveVipToDB(parseInt(telegramId), telegramName);

      // Crear invite link con 24h de vigencia
      const expireDate = Math.floor(Date.now() / 1000) + 24 * 60 * 60;
      const inviteData = await tgPost(token, 'createChatInviteLink', {
        chat_id: channel,
        expire_date: expireDate,
        member_limit: 1,
      });

      if (inviteData.ok) {
        const link = inviteData.result.invite_link;
        await tgPost(token, 'sendMessage', {
          chat_id: telegramId,
          parse_mode: 'HTML',
          text: `✅ <b>Pago confirmado — Suscripción VIP activa</b>\n\nÚsalo para unirte al canal privado:\n${link}\n\n⏳ El link expira en 24 horas — úsalo ya.\n📅 Tu suscripción es válida por 30 días.`,
        });
      }

      // Notificar al admin
      if (inbox) {
        await tgPost(token, 'sendMessage', {
          chat_id: inbox,
          parse_mode: 'HTML',
          text: `💰 <b>Nuevo pago Stripe</b>\n👤 ${telegramName} [${telegramId}]\n✅ Plan VIP activado automáticamente (30 días)`,
        });
      }
    }
  }

  return { statusCode: 200, body: JSON.stringify({ received: true }) };
};
