// The only place the console talks HTTP.
//
// The access token lives in this module's memory and nowhere else: not localStorage, not
// sessionStorage, not a readable cookie. The refresh token is an httpOnly cookie the browser
// sends to /v1/auth/* on its own; JavaScript never sees it.

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.error?.message ?? `request failed (${status})`);
    this.status = status;
    this.code = body?.error?.code ?? (status === 0 ? 'NETWORK' : 'UNKNOWN');
    this.reason = body?.error?.reason ?? null;
  }
}

let accessToken = null;
export const setAccessToken = (t) => { accessToken = t; };
export const clearAccessToken = () => { accessToken = null; };

async function request(method, path, body, { auth = true } = {}) {
  let res;
  try {
    res = await fetch(`/v1${path}`, {
      method,
      credentials: 'same-origin',
      headers: {
        ...(auth && accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, { error: { message: 'could not reach the server' } });
  }
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
  if (!res.ok) throw new ApiError(res.status, json);
  return json;
}

// Called when the server says the token is stale (a role or grant changed). Set by the app,
// which refreshes the token and reloads what the server says we may do.
let onStale = null;
export const setStaleHandler = (fn) => { onStale = fn; };

// Authenticated call. A stale token is refreshed once and the call retried; anything else
// surfaces to the caller, which must show it.
export async function api(method, path, body) {
  try {
    return await request(method, path, body);
  } catch (err) {
    if (err.code === 'TOKEN_STALE' && onStale) {
      await onStale();
      return request(method, path, body);
    }
    throw err;
  }
}

export const auth = {
  login: (email, password) => request('POST', '/auth/login', { email, password }, { auth: false }),
  refresh: (orgId) => request('POST', '/auth/refresh', orgId ? { orgId } : {}, { auth: false }),
  logout: () => request('POST', '/auth/logout', {}, { auth: false }),
  switchOrg: (orgId) => request('POST', '/auth/token', { orgId }),
  me: () => request('GET', '/auth/me'),
  peekInvite: (token) => request('GET', `/invites/${encodeURIComponent(token)}`, undefined, { auth: false }),
  acceptInvite: (token, body) => request('POST', `/invites/${encodeURIComponent(token)}/accept`, body, { auth: false }),
};
