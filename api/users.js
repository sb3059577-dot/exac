const { bcrypt, getJsonBody, getSupabase, json, methodNotAllowed, publicUser, requireAdmin, serviceErrorMessage } = require('./_lib/service');

async function handler(req, res) {
  if (!['GET', 'POST', 'DELETE'].includes(req.method)) return methodNotAllowed(res, ['GET', 'POST', 'DELETE']);
  try {
    const session = requireAdmin(req, res);
    if (!session) return;
    const client = getSupabase();

    if (req.method === 'GET') {
      const result = await client.from('service_users').select('id, username, role, display_name, created_at').order('created_at', { ascending: false });
      if (result.error) throw result.error;
      return json(res, 200, { users: (result.data || []).map(publicUser) });
    }

    if (req.method === 'DELETE') {
      const body = await getJsonBody(req);
      const id = String(body.id || '').trim();
      if (!id) return json(res, 400, { error: '缺少帳號編號' });
      if (id === session.user.id) return json(res, 400, { error: '不能刪除目前登入的帳號' });
      const selected = await client.from('service_users').select('id, role').eq('id', id).maybeSingle();
      if (selected.error) throw selected.error;
      if (!selected.data) return json(res, 404, { error: '找不到帳號' });
      if (selected.data.role === 'admin') {
        const admins = await client.from('service_users').select('id', { count: 'exact', head: true }).eq('role', 'admin');
        if (admins.error) throw admins.error;
        if ((admins.count || 0) <= 1) return json(res, 400, { error: '至少需保留一個管理員帳號' });
      }
      const deleted = await client.from('service_users').delete().eq('id', id);
      if (deleted.error) throw deleted.error;
      return json(res, 200, { ok: true });
    }

    const body = await getJsonBody(req);
    const displayName = String(body.displayName || '').trim();
    const username = String(body.username || '').trim();
    const password = String(body.password || '');
    const role = body.role === 'admin' ? 'admin' : 'agent';
    if (!displayName || !username || password.length < 4) return json(res, 400, { error: '請完整填寫帳號資料，密碼至少 4 碼' });
    const inserted = await client.from('service_users').insert({ username, password_hash: bcrypt.hashSync(password, 10), role, display_name: displayName });
    if (inserted.error) throw inserted.error;
    json(res, 200, { ok: true });
  } catch (error) {
    json(res, 500, { error: serviceErrorMessage(error, '帳號處理失敗') });
  }
}

module.exports = handler;
