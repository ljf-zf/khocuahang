const COOKIE_NAME = 'kho_session';
const SESSION_SECONDS = 60 * 60 * 12;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
  });
}

function base64url(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function unbase64url(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'],
  );
}

async function createSession(secret) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(new TextEncoder().encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const payload = base64url(new TextEncoder().encode(JSON.stringify({ iat: now, exp: now + SESSION_SECONDS })));
  const input = `${header}.${payload}`;
  const signature = await crypto.subtle.sign('HMAC', await hmacKey(secret), new TextEncoder().encode(input));
  return `${input}.${base64url(new Uint8Array(signature))}`;
}

async function verifySession(request, secret) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(new RegExp(`(?:^|;\\s*)${COOKIE_NAME}=([^;]+)`));
  if (!match) return false;
  const parts = match[1].split('.');
  if (parts.length !== 3) return false;
  const input = `${parts[0]}.${parts[1]}`;
  let signature;
  let payload;
  try {
    signature = unbase64url(parts[2]);
    payload = JSON.parse(new TextDecoder().decode(unbase64url(parts[1])));
  } catch { return false; }
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return false;
  try {
    return await crypto.subtle.verify('HMAC', await hmacKey(secret), signature, new TextEncoder().encode(input));
  } catch { return false; }
}

function cookie(value, request, maxAge) {
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  return `${COOKIE_NAME}=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secure}`;
}

async function readBody(request, maxBytes = 1_500_000) {
  const raw = await request.text();
  if (new TextEncoder().encode(raw).length > maxBytes) throw new Error('Dữ liệu gửi lên quá lớn.');
  return JSON.parse(raw);
}

function extensionCorsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Vary': 'Origin',
  };
}
function hasValidSyncKey(request, env) {
  const expected = String(env.SYNC_API_KEY || '');
  const supplied = String(request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
  return Boolean(expected && supplied && constantTimeEqual(expected, supplied));
}
async function sha256Hex(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
}
function classifyExtensionOrder(order) {
  const fields = Array.isArray(order.statusFields) ? order.statusFields : [];
  // Phân biệt cờ đã hủy với cờ can_cancel/cancelable (có thể hủy).
  const cancellationFlag = /(^|[._])(is_cancelled|is_canceled|cancelled|canceled|cancelled_flag|canceled_flag|cancel_flag|cancellation_flag|cancel_status|cancellation_status|is_voided|voided|is_void|is_huy|da_huy)([._]|$)/i;
  const cancellationDate = /(cancelled_at|canceled_at|cancelled_on|canceled_on|cancel_time|canceled_time|cancelled_time|cancellation_date|voided_at)/i;
  for (const field of fields) {
    const normalizedKey = String(field.key || '').replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
    if (cancellationFlag.test(normalizedKey) && (field.value === true || field.value === 1 || ['true', '1', 'yes'].includes(String(field.value).toLowerCase()))) return 'cancelled';
    const dateValue = String(field.value || '').trim().toLowerCase();
    if (cancellationDate.test(normalizedKey) && dateValue && !['0', 'false', 'null', '0000-00-00'].includes(dateValue)) return 'cancelled';
    if (/(status|reason|action)/i.test(String(field.key || '')) && typeof field.value === 'string' && /(cancel|canceled|cancelled|void|đã hủy|da huy|hủy đơn|huy don)/i.test(field.value)) return 'cancelled';
  }
  if (order.cancellationExplicit === true) return 'cancelled';
  const rawStatuses = [order.channelOrderStatus, order.sapoOrderStatus, order.status].map(x => String(x || '')).join(' ');
  if (/(cancel|canceled|cancelled|void|đã hủy|da huy|hủy đơn|huy don)/i.test(rawStatuses)) return 'cancelled';
  if (String(order.channelOrderStatus || '').toUpperCase() === 'PROCESSED') return 'processed';
  if (['READY_TO_SHIP', 'RETRY_SHIP'].includes(String(order.channelOrderStatus || '').toUpperCase()) && String(order.sapoOrderStatus || '').toLowerCase() === 'pending') return 'pending';
  return 'unknown';
}
function sanitizeExtensionOrder(input) {
  const orderKey = String(input.orderKey || '').trim().slice(0, 250);
  if (!orderKey) return null;
  const items = Array.isArray(input.items) ? input.items.slice(0, 100).map(item => ({
    sku: String(item.sku || '').trim().slice(0, 120),
    name: String(item.name || '').trim().slice(0, 240),
    variant: String(item.variant || '').trim().slice(0, 240),
    quantity: Math.max(0, Math.min(1_000_000, Number(item.quantity) || 0)),
  })) : [];
  const order = {
    orderKey,
    id: String(input.id || '').slice(0, 120),
    orderNumber: String(input.orderNumber || '').slice(0, 160),
    connectionId: String(input.connectionId || '').slice(0, 120),
    channel: String(input.channel || '').slice(0, 160),
    channelOrderStatus: String(input.channelOrderStatus || '').slice(0, 120),
    sapoOrderStatus: String(input.sapoOrderStatus || '').slice(0, 120),
    status: String(input.status || '').slice(0, 120),
    statusFields: Array.isArray(input.statusFields) ? input.statusFields.slice(0, 24).map(x => ({ key: String(x.key || '').slice(0, 120), value: typeof x.value === 'string' ? x.value.slice(0, 120) : (typeof x.value === 'number' || typeof x.value === 'boolean' ? x.value : null) })) : [],
    cancellationExplicit: input.cancellationExplicit === true,
    createdAt: String(input.createdAt || '').slice(0, 80),
    updatedAt: String(input.updatedAt || '').slice(0, 80),
    cancelledAt: String(input.cancelledAt || '').slice(0, 80),
    items,
    phase: input.phase === 'baseline' ? 'baseline' : 'live',
    observedAt: String(input.observedAt || new Date().toISOString()).slice(0, 80),
  };
  order.classification = classifyExtensionOrder(order);
  return order;
}
async function handleExtensionPing(request, env) {
  if (!env.SYNC_API_KEY) return json({ error: 'Máy chủ chưa cấu hình SYNC_API_KEY.' }, 503, extensionCorsHeaders());
  if (!hasValidSyncKey(request, env)) return json({ error: 'SYNC_API_KEY không đúng.' }, 401, extensionCorsHeaders());
  return json({ ok: true, service: 'kho-sapo-extension-sync', alias: env.SAPO_ALIAS || 'goldentech', serverTime: new Date().toISOString() }, 200, extensionCorsHeaders());
}
async function handleExtensionOrders(request, env) {
  if (!env.DB) return json({ error: 'Máy chủ chưa gắn D1 database.' }, 503, extensionCorsHeaders());
  if (!env.SYNC_API_KEY) return json({ error: 'Máy chủ chưa cấu hình SYNC_API_KEY.' }, 503, extensionCorsHeaders());
  if (!hasValidSyncKey(request, env)) return json({ error: 'SYNC_API_KEY không đúng.' }, 401, extensionCorsHeaders());
  let body;
  try { body = await readBody(request, 1_200_000); }
  catch (error) { return json({ error: error.message || 'JSON không hợp lệ.' }, 400, extensionCorsHeaders()); }
  const agentId = String(body.agentId || '').trim().slice(0, 100);
  if (!agentId || !Array.isArray(body.orders) || body.orders.length > 60) return json({ error: 'Thiếu agentId hoặc mỗi lần gửi vượt quá 60 đơn.' }, 400, extensionCorsHeaders());
  const batchPhase = body.phase === 'baseline' ? 'baseline' : 'live';
  const observedAt = String(body.observedAt || new Date().toISOString()).slice(0, 80);
  let changed = 0, created = 0, cancelled = 0, unknown = 0, skipped = 0;
  for (const raw of body.orders) {
    const order = sanitizeExtensionOrder({ ...raw, phase: raw.phase || batchPhase, observedAt: raw.observedAt || observedAt });
    if (!order) { skipped++; continue; }
    const previous = await env.DB.prepare('SELECT fingerprint, classification, first_seen_at, payload_json FROM sapo_extension_orders WHERE order_key = ?').bind(order.orderKey).first();
    const fingerprintSource = JSON.stringify({
      orderNumber: order.orderNumber, connectionId: order.connectionId, channel: order.channel,
      channelOrderStatus: order.channelOrderStatus, sapoOrderStatus: order.sapoOrderStatus,
      status: order.status, statusFields: order.statusFields, classification: order.classification,
      cancellationExplicit: order.cancellationExplicit, createdAt: order.createdAt,
      updatedAt: order.updatedAt, cancelledAt: order.cancelledAt, items: order.items,
    });
    const fingerprint = await sha256Hex(fingerprintSource);
    const now = new Date().toISOString();
    const wasChanged = !previous || previous.fingerprint !== fingerprint;
    let eventType = null;
    if (wasChanged) {
      if (!previous) eventType = order.phase === 'baseline' ? 'baseline' : 'new';
      else if (previous.classification !== 'cancelled' && order.classification === 'cancelled') eventType = 'cancelled';
      else if (previous.classification === 'cancelled' && ['pending', 'processed'].includes(order.classification)) eventType = 'reopened';
      else eventType = 'updated';
      changed++;
      if (!previous) created++;
    }
    if (order.classification === 'cancelled') cancelled++;
    if (order.classification === 'unknown') unknown++;
    let priorPayload = {}; try { priorPayload = JSON.parse(previous?.payload_json || '{}'); } catch {}
    const payloadJson = JSON.stringify({ ...order, fingerprint, lastEventType: eventType || priorPayload.lastEventType || 'unchanged' });
    const snapshotStatement = env.DB.prepare(`INSERT INTO sapo_extension_orders (
      order_key, order_id, order_number, connection_id, channel, channel_order_status,
      sapo_order_status, status, classification, cancellation_explicit, created_at,
      source_updated_at, first_seen_at, last_seen_at, last_changed_at, fingerprint, phase, payload_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(order_key) DO UPDATE SET
      order_id=excluded.order_id, order_number=excluded.order_number, connection_id=excluded.connection_id,
      channel=excluded.channel, channel_order_status=excluded.channel_order_status,
      sapo_order_status=excluded.sapo_order_status, status=excluded.status,
      classification=excluded.classification, cancellation_explicit=excluded.cancellation_explicit,
      created_at=excluded.created_at, source_updated_at=excluded.source_updated_at,
      last_seen_at=excluded.last_seen_at,
      last_changed_at=CASE WHEN sapo_extension_orders.fingerprint != excluded.fingerprint THEN excluded.last_changed_at ELSE sapo_extension_orders.last_changed_at END,
      fingerprint=excluded.fingerprint, phase=excluded.phase, payload_json=excluded.payload_json`)
      .bind(order.orderKey, order.id || order.orderKey, order.orderNumber || order.id || order.orderKey,
        order.connectionId, order.channel, order.channelOrderStatus, order.sapoOrderStatus, order.status,
        order.classification, order.cancellationExplicit ? 1 : 0, order.createdAt, order.updatedAt,
        previous?.first_seen_at || now, now, wasChanged ? now : (previous?.first_seen_at || now), fingerprint, order.phase, payloadJson);
    if (wasChanged) {
      const eventId = await sha256Hex(order.orderKey + '|' + (previous?.fingerprint || 'none') + '>' + fingerprint);
      const eventStatement = env.DB.prepare(`INSERT OR IGNORE INTO sapo_extension_events
        (event_id, order_key, event_type, classification, observed_at, fingerprint, payload_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .bind(eventId, order.orderKey, eventType, order.classification, observedAt, fingerprint, payloadJson);
      // Ghi snapshot và event trong cùng transaction để không mất lịch sử nếu request lỗi giữa chừng.
      await env.DB.batch([snapshotStatement, eventStatement]);
    } else {
      await snapshotStatement.run();
    }
  }
  const now = new Date().toISOString();
  const seenKeys = Array.isArray(body.seenOrderKeys) ? [...new Set(body.seenOrderKeys.map(x => String(x || '').trim().slice(0, 250)).filter(Boolean))].slice(0, 600) : [];
  if (seenKeys.length) {
    // Giảm D1 row writes: chỉ refresh last_seen_at tối đa mỗi 6 giờ cho một đơn.
    // Mỗi câu SQL dùng tối đa 92 bind params (now + 90 keys + cutoff).
    const seenCutoff = new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString();
    for (let offset = 0; offset < seenKeys.length; offset += 90) {
      const chunk = seenKeys.slice(offset, offset + 90);
      const placeholders = chunk.map(() => '?').join(',');
      await env.DB.prepare(
        `UPDATE sapo_extension_orders
         SET last_seen_at = ?
         WHERE order_key IN (${placeholders})
           AND last_seen_at < ?`
      ).bind(now, ...chunk, seenCutoff).run();
    }
  }
  const priorAgent = await env.DB.prepare('SELECT first_seen_at, last_changed_count FROM sapo_extension_agents WHERE agent_id = ?').bind(agentId).first();
  const reportedChanged = body.orders.length ? changed : Number(priorAgent?.last_changed_count || 0);
  await env.DB.prepare(`INSERT INTO sapo_extension_agents
    (agent_id, device_label, first_seen_at, last_seen_at, last_poll_at, last_error, last_received_count, last_changed_count, baseline_complete)
    VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?)
    ON CONFLICT(agent_id) DO UPDATE SET device_label=excluded.device_label, last_seen_at=excluded.last_seen_at,
      last_poll_at=excluded.last_poll_at, last_error=NULL, last_received_count=excluded.last_received_count,
      last_changed_count=excluded.last_changed_count,
      baseline_complete=MAX(sapo_extension_agents.baseline_complete, excluded.baseline_complete)`)
    .bind(agentId, String(body.deviceLabel || 'Browser extension').slice(0, 120), priorAgent?.first_seen_at || now, now, now,
      Math.max(0, Number(body.observedCount ?? body.orders.length) || 0), reportedChanged, body.baselineComplete ? 1 : 0).run();
  return json({ ok: true, received: body.orders.length, changed, created, cancelled, unknown, skipped, acceptedAt: now }, 200, extensionCorsHeaders());
}
async function getExtensionSyncStatus(env) {
  const agent = await env.DB.prepare('SELECT * FROM sapo_extension_agents ORDER BY last_seen_at DESC LIMIT 1').first();
  const totals = await env.DB.prepare(`SELECT COUNT(*) AS total,
    SUM(CASE WHEN classification='cancelled' THEN 1 ELSE 0 END) AS cancelled,
    SUM(CASE WHEN classification='unknown' THEN 1 ELSE 0 END) AS unknown,
    SUM(CASE WHEN classification='pending' THEN 1 ELSE 0 END) AS pending,
    SUM(CASE WHEN classification='processed' THEN 1 ELSE 0 END) AS processed,
    MAX(last_seen_at) AS last_seen_at FROM sapo_extension_orders`).first();
  const events = await env.DB.prepare(`SELECT event_type, COUNT(*) AS count FROM sapo_extension_events GROUP BY event_type`).all();
  return { ok: true, agent: agent || null, totals: totals || {}, events: events?.results || [] };
}
async function getExtensionOrders(url, env) {
  const allowed = new Set(['all', 'cancelled', 'unknown', 'pending', 'processed']);
  const filter = allowed.has(url.searchParams.get('status')) ? url.searchParams.get('status') : 'all';
  const limit = Math.max(1, Math.min(200, Number(url.searchParams.get('limit')) || 100));
  const offset = Math.max(0, Number(url.searchParams.get('offset')) || 0);
  const params = [];
  let where = '';
  if (filter !== 'all') { where = 'WHERE classification = ?'; params.push(filter); }
  const result = await env.DB.prepare(`SELECT order_key, order_id, order_number, connection_id, channel,
    channel_order_status, sapo_order_status, status, classification, cancellation_explicit,
    created_at, source_updated_at, first_seen_at, last_seen_at, last_changed_at, phase, payload_json
    FROM sapo_extension_orders ${where} ORDER BY last_seen_at DESC LIMIT ? OFFSET ?`)
    .bind(...params, limit, offset).all();
  const countQuery = filter === 'all'
    ? env.DB.prepare('SELECT COUNT(*) AS count FROM sapo_extension_orders')
    : env.DB.prepare('SELECT COUNT(*) AS count FROM sapo_extension_orders WHERE classification = ?').bind(filter);
  const count = await countQuery.first();
  return { ok: true, status: filter, total: Number(count?.count || 0), orders: (result.results || []).map(row => {
    let payload = {}; try { payload = JSON.parse(row.payload_json || '{}'); } catch {}
    return { ...row, payload };
  }) };
}


function b64(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}
function unb64(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
async function encryptionKey(secret) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(secret));
  return crypto.subtle.importKey('raw', digest, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function encryptSapoToken(token, secret) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await encryptionKey(secret);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(token));
  return `${b64(iv)}.${b64(new Uint8Array(encrypted))}`;
}
async function decryptSapoToken(value, secret) {
  const [ivText, cipherText] = String(value || '').split('.');
  if (!ivText || !cipherText) throw new Error('Không đọc được access token đã lưu.');
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(ivText) }, await encryptionKey(secret), unb64(cipherText));
  return new TextDecoder().decode(plain);
}
function sapoAlias(env) {
  return String(env.SAPO_ALIAS || 'goldentech').trim().replace(/^https?:\/\//i, '').replace(/\.mysapogo\.com.*$/i, '').replace(/\.mysapogo\.com$/i, '');
}
function sapoHost(env) { return `${sapoAlias(env)}.mysapogo.com`; }
function oauthStateCookie(value, request, maxAge = 600) {
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  return `sapo_oauth_state=${value}; HttpOnly; SameSite=Lax; Path=/api/sapo/callback; Max-Age=${maxAge}${secure}`;
}
function constantTimeEqual(a, b) {
  const aa = new TextEncoder().encode(String(a));
  const bb = new TextEncoder().encode(String(b));
  let diff = aa.length ^ bb.length;
  for (let i = 0; i < Math.max(aa.length, bb.length); i++) diff |= (aa[i] || 0) ^ (bb[i] || 0);
  return diff === 0;
}
async function verifySapoOAuthHmac(url, secret) {
  const supplied = url.searchParams.get('hmac');
  if (!supplied) return false;
  const pairs = Array.from(url.searchParams.entries()).filter(([key]) => key !== 'hmac');
  pairs.sort((a, b) => a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]));
  const message = pairs.map(([key, value]) => `${key}=${value}`).join('&');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const digest = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return constantTimeEqual(b64(new Uint8Array(digest)), supplied);
}
async function getSapoConnection(env) {
  return env.DB.prepare('SELECT alias, access_token_encrypted, connected_at, last_test_at, last_test_status, last_test_error FROM sapo_connection WHERE id = 1').first();
}
async function getSapoToken(env) {
  const row = await getSapoConnection(env);
  if (!row?.access_token_encrypted) return null;
  if (!env.AUTH_SECRET) throw new Error('Máy chủ chưa cấu hình AUTH_SECRET.');
  return decryptSapoToken(row.access_token_encrypted, env.AUTH_SECRET);
}
async function sapoRequest(env, token, path) {
  const url = `https://${sapoHost(env)}/admin/${path.replace(/^\//, '')}`;
  const response = await fetch(url, {
    method: 'GET',
    headers: { 'X-Sapo-Access-Token': token, 'Accept': 'application/json', 'Content-Type': 'application/json' },
  });
  const raw = await response.text();
  let body;
  try { body = JSON.parse(raw); } catch { body = { raw: raw.slice(0, 1200) }; }
  if (!response.ok) {
    const msg = body?.errors ? JSON.stringify(body.errors) : body?.message || body?.raw || `HTTP ${response.status}`;
    throw new Error(`Sapo API trả lỗi ${response.status}: ${String(msg).slice(0, 500)}`);
  }
  return body;
}
function extractSapoOrders(payload) {
  if (Array.isArray(payload?.orders)) return payload.orders;
  if (Array.isArray(payload?.data?.orders)) return payload.data.orders;
  if (Array.isArray(payload?.data)) return payload.data;
  if (Array.isArray(payload)) return payload;
  throw new Error(`Sapo phản hồi không có danh sách orders. Các trường nhận được: ${Object.keys(payload || {}).join(', ') || 'không rõ'}`);
}
function normalizeSapoOrder(order, knownSkus) {
  const lines = Array.isArray(order.line_items) ? order.line_items : Array.isArray(order.items) ? order.items : [];
  const itemMap = new Map();
  for (const line of lines) {
    const sku = String(line.sku || line.variant_sku || line.item_sku || '').trim();
    const quantity = Number(line.quantity ?? line.qty ?? 0);
    if (!sku || !Number.isFinite(quantity) || quantity <= 0) continue;
    const key = sku.toLowerCase();
    const old = itemMap.get(key) || { sku, name: String(line.name || line.title || line.product_name || ''), quantity: 0 };
    old.quantity += quantity;
    itemMap.set(key, old);
  }
  const items = Array.from(itemMap.values());
  return {
    id: String(order.id ?? order.order_id ?? ''),
    name: String(order.name || order.code || order.order_code || (order.id ? `#${order.id}` : 'Đơn chưa có mã')),
    modifiedOn: order.modified_on || order.updated_at || order.updated_on || null,
    createdOn: order.created_on || order.created_at || order.issued_at || null,
    status: String(order.status || order.fulfillment_status || 'unknown'),
    financialStatus: String(order.financial_status || ''),
    sourceName: String(order.source_name || order.channel_name || order.channel || ''),
    cancelled: Boolean(order.cancelled_on || order.cancelled_at || String(order.status || '').toLowerCase() === 'cancelled'),
    items: items.map(x => ({ ...x, matched: knownSkus.has(x.sku.toLowerCase()) })),
  };
}
async function handleSapoCallback(request, env) {
  const url = new URL(request.url);
  const cookies = request.headers.get('Cookie') || '';
  const stateMatch = cookies.match(/(?:^|;\s*)sapo_oauth_state=([^;]+)/);
  const stateCookie = stateMatch?.[1] || '';
  const stateParam = url.searchParams.get('state') || '';
  const clearState = oauthStateCookie('', request, 0);
  const safeMessage = message => String(message).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const fail = (message, status = 400) => new Response(`<html lang="vi"><meta charset="utf-8"><title>Kết nối Sapo</title><body style="font-family:Arial;padding:32px"><h2>Chưa kết nối được Sapo</h2><p>${safeMessage(message)}</p><p><a href="/">Quay lại Kho Cửa Hàng</a></p></body></html>`, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Set-Cookie': clearState, 'Cache-Control': 'no-store' } });
  if (!env.SAPO_API_KEY || !env.SAPO_API_SECRET || !env.SAPO_REDIRECT_URI) return fail('Máy chủ chưa cấu hình API Key, API Secret hoặc Redirect URI.');
  if (!env.AUTH_SECRET) return fail('Máy chủ chưa cấu hình AUTH_SECRET để mã hóa token.', 503);
  if (!stateCookie || (stateParam && !constantTimeEqual(stateCookie, stateParam))) return fail('Phiên OAuth hết hạn hoặc không khớp. Hãy bắt đầu kết nối lại.');
  if (!await verifySapoOAuthHmac(url, env.SAPO_API_SECRET)) return fail('Chữ ký xác thực từ Sapo không hợp lệ.');
  const store = String(url.searchParams.get('store') || '').toLowerCase();
  if (store && store !== sapoHost(env) && store !== sapoAlias(env)) return fail('Tên cửa hàng trả về không khớp với goldentech.mysapogo.com.');
  const code = url.searchParams.get('code');
  if (!code) return fail('Sapo không trả về authorization code.');
  try {
    const form = new URLSearchParams({ client_id: env.SAPO_API_KEY, client_secret: env.SAPO_API_SECRET, code });
    const tokenResponse = await fetch(`https://${sapoHost(env)}/admin/oauth/access_token`, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' }, body: form,
    });
    const tokenRaw = await tokenResponse.text();
    let tokenBody;
    try { tokenBody = JSON.parse(tokenRaw); } catch { tokenBody = {}; }
    const accessToken = tokenBody.access_token || tokenBody?.data?.access_token;
    if (!tokenResponse.ok || !accessToken) throw new Error(`Không lấy được access_token (HTTP ${tokenResponse.status}). ${String(tokenBody.error || tokenRaw).slice(0, 300)}`);
    const encrypted = await encryptSapoToken(accessToken, env.AUTH_SECRET);
    await env.DB.prepare(`INSERT INTO sapo_connection (id, alias, access_token_encrypted, connected_at, last_test_status)
      VALUES (1, ?, ?, ?, 'connected')
      ON CONFLICT(id) DO UPDATE SET alias=excluded.alias, access_token_encrypted=excluded.access_token_encrypted, connected_at=excluded.connected_at, last_test_status='connected', last_test_error=NULL`)
      .bind(sapoAlias(env), encrypted, new Date().toISOString()).run();
    return new Response(null, { status: 302, headers: { Location: '/?sapo=connected', 'Set-Cookie': clearState, 'Cache-Control': 'no-store' } });
  } catch (error) {
    return fail(String(error?.message || error), 502);
  }
}
async function startSapoOAuth(request, env) {
  if (!env.SAPO_API_KEY || !env.SAPO_API_SECRET || !env.SAPO_REDIRECT_URI || !env.SAPO_SCOPES) {
    return json({ error: 'Thiếu SAPO_API_KEY, SAPO_API_SECRET, SAPO_REDIRECT_URI hoặc SAPO_SCOPES. Hãy xin Sapo mở API Omni và cấp thông tin qua email.' }, 503);
  }
  const state = base64url(crypto.getRandomValues(new Uint8Array(24)));
  const authorize = new URL(`https://${sapoHost(env)}/admin/oauth/authorize`);
  authorize.searchParams.set('client_id', env.SAPO_API_KEY);
  authorize.searchParams.set('scope', env.SAPO_SCOPES);
  authorize.searchParams.set('redirect_uri', env.SAPO_REDIRECT_URI);
  authorize.searchParams.set('state', state);
  return new Response(null, { status: 302, headers: { Location: authorize.toString(), 'Set-Cookie': oauthStateCookie(state, request), 'Cache-Control': 'no-store' } });
}
async function handleSapoTest(env) {
  const token = await getSapoToken(env);
  if (!token) return json({ error: 'Chưa kết nối Sapo. Hãy bấm Kết nối Sapo Omni trước.' }, 409);
  try {
    const payload = await sapoRequest(env, token, 'orders.json?limit=10&page=1&status=any');
    const rawOrders = extractSapoOrders(payload);
    const stateRow = await env.DB.prepare('SELECT payload FROM app_state WHERE id = 1').first();
    let inventory = { products: [] };
    try { if (stateRow?.payload) inventory = JSON.parse(stateRow.payload); } catch {}
    const knownSkus = new Set((inventory.products || []).map(p => String(p.sku || '').toLowerCase()));
    const orders = rawOrders.map(o => normalizeSapoOrder(o, knownSkus)).filter(o => o.id || o.items.length);
    await env.DB.prepare('UPDATE sapo_connection SET last_test_at=?, last_test_status=?, last_test_error=NULL WHERE id=1').bind(new Date().toISOString(), 'ok').run();
    return json({ ok: true, alias: sapoAlias(env), count: orders.length, orders, matchedSkuCount: orders.reduce((n, o) => n + o.items.filter(i => i.matched).length, 0), unmatchedSkuCount: orders.reduce((n, o) => n + o.items.filter(i => !i.matched).length, 0), checkedAt: new Date().toISOString() });
  } catch (error) {
    await env.DB.prepare('UPDATE sapo_connection SET last_test_at=?, last_test_status=?, last_test_error=? WHERE id=1').bind(new Date().toISOString(), 'error', String(error?.message || error).slice(0, 500)).run();
    return json({ error: String(error?.message || error) }, 502);
  }
}

async function handleApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path.startsWith('/api/extension/sapo/') && request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: extensionCorsHeaders() });
  }
  if (path === '/api/extension/sapo/ping' && request.method === 'GET') return handleExtensionPing(request, env);
  if (path === '/api/extension/sapo/orders' && request.method === 'POST') return handleExtensionOrders(request, env);

  if (path === '/api/sapo/callback' && request.method === 'GET') return handleSapoCallback(request, env);

  if (path === '/api/health' && request.method === 'GET') {
    return json({ ok: true, service: 'kho-cua-hang', database: Boolean(env.DB) });
  }

  if (path === '/api/login' && request.method === 'POST') {
    if (!env.APP_PASSWORD || !env.AUTH_SECRET) return json({ error: 'Máy chủ chưa cấu hình APP_PASSWORD hoặc AUTH_SECRET.' }, 503);
    let body;
    try { body = await readBody(request, 10_000); }
    catch { return json({ error: 'Dữ liệu đăng nhập không hợp lệ.' }, 400); }
    const supplied = String(body.password || '');
    const expected = String(env.APP_PASSWORD);
    // Compare all characters to avoid an early-exit timing difference.
    let diff = supplied.length ^ expected.length;
    const n = Math.max(supplied.length, expected.length);
    for (let i = 0; i < n; i++) diff |= (supplied.charCodeAt(i) || 0) ^ (expected.charCodeAt(i) || 0);
    if (diff !== 0) return json({ error: 'Mật khẩu không đúng.' }, 401);
    const token = await createSession(env.AUTH_SECRET);
    return json({ ok: true }, 200, { 'Set-Cookie': cookie(token, request, SESSION_SECONDS) });
  }

  if (path === '/api/logout' && request.method === 'POST') {
    return json({ ok: true }, 200, { 'Set-Cookie': cookie('', request, 0) });
  }

  if (path.startsWith('/api/')) {
    const valid = env.AUTH_SECRET && await verifySession(request, env.AUTH_SECRET);
    if (!valid) return json({ error: 'Phiên đăng nhập hết hạn. Vui lòng đăng nhập lại.' }, 401);
  }

  if (path === '/api/extension/sapo/status' && request.method === 'GET') return json(await getExtensionSyncStatus(env));
  if (path === '/api/extension/sapo/orders' && request.method === 'GET') return json(await getExtensionOrders(url, env));
  if (path === '/api/extension/sapo/events' && request.method === 'GET') {
    const limit = Math.max(1, Math.min(200, Number(url.searchParams.get('limit')) || 100));
    const result = await env.DB.prepare('SELECT event_id, order_key, event_type, classification, observed_at, payload_json FROM sapo_extension_events ORDER BY observed_at DESC LIMIT ?').bind(limit).all();
    return json({ ok: true, events: (result.results || []).map(row => { let payload={}; try { payload=JSON.parse(row.payload_json||'{}'); } catch {} return { ...row, payload }; }) });
  }

  if (path === '/api/sapo/connect' && request.method === 'GET') return startSapoOAuth(request, env);

  if (path === '/api/sapo/status' && request.method === 'GET') {
    const row = await getSapoConnection(env);
    return json({
      configured: Boolean(env.SAPO_API_KEY && env.SAPO_API_SECRET && env.SAPO_REDIRECT_URI && env.SAPO_SCOPES),
      connected: Boolean(row?.access_token_encrypted),
      alias: row?.alias || sapoAlias(env),
      connectedAt: row?.connected_at || null,
      lastTestAt: row?.last_test_at || null,
      lastTestStatus: row?.last_test_status || null,
      lastTestError: row?.last_test_error || null,
      redirectUri: env.SAPO_REDIRECT_URI || `${url.origin}/api/sapo/callback`,
      scopes: env.SAPO_SCOPES || null,
    });
  }

  if (path === '/api/sapo/test' && request.method === 'POST') return handleSapoTest(env);

  if (path === '/api/sapo/disconnect' && request.method === 'POST') {
    await env.DB.prepare('DELETE FROM sapo_connection WHERE id=1').run();
    return json({ ok: true });
  }

  if (path === '/api/state' && request.method === 'GET') {
    const row = await env.DB.prepare('SELECT payload, revision, updated_at FROM app_state WHERE id = 1').first();
    if (!row) return json({ state: null, revision: 0, updatedAt: null });
    let state;
    try { state = JSON.parse(row.payload); }
    catch { return json({ error: 'Dữ liệu kho trên máy chủ không đọc được.' }, 500); }
    return json({ state, revision: row.revision, updatedAt: row.updated_at });
  }

  if (path === '/api/state' && request.method === 'PUT') {
    let body;
    try { body = await readBody(request); }
    catch (e) { return json({ error: e.message || 'JSON không hợp lệ.' }, 400); }
    const state = body.state;
    const expectedRevision = Number(body.revision);
    if (!state || !Array.isArray(state.products) || !Array.isArray(state.history) || !Number.isInteger(expectedRevision) || expectedRevision < 0) {
      return json({ error: 'Cấu trúc dữ liệu kho không hợp lệ.' }, 400);
    }
    if (state.products.length > 100_000 || state.history.length > 500_000) return json({ error: 'Dữ liệu vượt giới hạn cho phép.' }, 413);
    const payload = JSON.stringify(state);
    if (new TextEncoder().encode(payload).length > 1_500_000) return json({ error: 'Dữ liệu kho vượt giới hạn 1.5 MB.' }, 413);
    const now = new Date().toISOString();
    let result;
    if (expectedRevision === 0) {
      result = await env.DB.prepare(
        'INSERT OR IGNORE INTO app_state (id, payload, revision, updated_at) VALUES (1, ?, 1, ?)'
      ).bind(payload, now).run();
    } else {
      result = await env.DB.prepare(
        'UPDATE app_state SET payload = ?, revision = revision + 1, updated_at = ? WHERE id = 1 AND revision = ?'
      ).bind(payload, now, expectedRevision).run();
    }
    if (!result.meta || result.meta.changes !== 1) {
      const current = await env.DB.prepare('SELECT revision FROM app_state WHERE id = 1').first();
      return json({ error: 'Dữ liệu đã được cập nhật từ một thiết bị khác.', revision: current?.revision ?? 0 }, 409);
    }
    return json({ ok: true, revision: expectedRevision + 1, updatedAt: now });
  }

  return json({ error: 'Không tìm thấy API.' }, 404);
}

function addSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (new URL(response.url || 'https://example.com').protocol === 'https:') headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (url.pathname.startsWith('/api/')) {
        const response = await handleApi(request, env);
        const headers = new Headers(response.headers);
        headers.set('X-Content-Type-Options', 'nosniff');
        headers.set('X-Frame-Options', 'DENY');
        headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
        headers.set('Cache-Control', 'no-store');
        return new Response(response.body, { status: response.status, headers });
      }
      if (!env.ASSETS) return new Response('Static assets binding is missing.', { status: 500 });
      const assetResponse = await env.ASSETS.fetch(request);
      const headers = new Headers(assetResponse.headers);
      headers.set('X-Content-Type-Options', 'nosniff');
      headers.set('X-Frame-Options', 'DENY');
      headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
      return new Response(assetResponse.body, { status: assetResponse.status, headers });
    } catch (error) {
      const path = new URL(request.url).pathname;
      const headers = path.startsWith('/api/extension/sapo/') ? extensionCorsHeaders() : {};
      return json({ error: 'Lỗi máy chủ.', detail: error?.message || String(error) }, 500, headers);
    }
  },
};
