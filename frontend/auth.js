/**
 * simple-jwt-auth frontend module
 *
 * Usage:
 *   import { SimpleJwtAuth } from './auth.js';
 *   const auth = new SimpleJwtAuth({ baseUrl: '/api/auth' });
 *   auth.addAuthListener(loggedIn => console.log('logged in?', loggedIn));
 *
 *   await auth.login('user@example.com', 'password');
 *   auth.loginWithGoogle();
 *   const res = await auth.fetch('/api/posts');   // auto-retries once after 401 + refresh
 *   await auth.logout();
 */

export class AuthError extends Error {
  constructor(message, { status = 0, body = null } = {}) {
    super(message);
    this.name = 'AuthError';
    this.status = status;
    this.body = body;
  }
}

export class SimpleJwtAuth {
  #accessToken = null;
  #baseUrl;
  #listeners = new Set();
  #refreshPromise = null;
  #oAuthError = null;

  constructor({ baseUrl = '/api/auth', onAuthChange } = {}) {
    this.#baseUrl = baseUrl;
    if (typeof onAuthChange === 'function') this.addAuthListener(onAuthChange);
    // Defer OAuth callback handling so the constructor returns before any listener fires.
    if (typeof window !== 'undefined') {
      queueMicrotask(() => { this.#handlePageLoad(); });
    }
  }

  get isLoggedIn() {
    return this.#accessToken !== null;
  }

  /** Latest OAuth error surfaced by redirect, if any. Cleared once read. */
  get lastOAuthError() {
    const err = this.#oAuthError;
    this.#oAuthError = null;
    return err;
  }

  addAuthListener(fn) {
    this.#listeners.add(fn);
    return () => this.#listeners.delete(fn);
  }

  async login(username, password) {
    const res = await fetch(`${this.#baseUrl}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      },
      credentials: 'include',
      body: JSON.stringify({ username, password }),
    });

    if (!res.ok) {
      const body = await readBodySafely(res);
      throw new AuthError('Login failed', { status: res.status, body });
    }
    const { accessToken } = await res.json();
    this.#setAccessToken(accessToken);
  }

  loginWithGoogle() {
    window.location.href = `${this.#baseUrl}/oauth/google`;
  }

  async logout() {
    try {
      await fetch(`${this.#baseUrl}/logout`, {
        method: 'POST',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        credentials: 'include',
      });
    } catch {
      // network error — still clear local state
    }
    this.#setAccessToken(null);
  }

  async fetch(url, options = {}) {
    let res = await this.#authFetch(url, options);

    if (res.status === 401 && this.#accessToken !== null) {
      const refreshed = await this.#refresh();
      if (refreshed) {
        res = await this.#authFetch(url, options);
      } else {
        this.#setAccessToken(null);
      }
    }
    return res;
  }

  #refresh() {
    if (this.#refreshPromise) return this.#refreshPromise;
    this.#refreshPromise = this.#doRefresh()
      .finally(() => { this.#refreshPromise = null; });
    return this.#refreshPromise;
  }

  async #doRefresh() {
    try {
      const res = await fetch(`${this.#baseUrl}/refresh`, {
        method: 'POST',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        credentials: 'include',
      });
      if (!res.ok) return false;
      const { accessToken } = await res.json();
      this.#setAccessToken(accessToken);
      return true;
    } catch {
      return false;
    }
  }

  #authFetch(url, options) {
    const headers = new Headers(options.headers || {});
    if (this.#accessToken) {
      headers.set('Authorization', `Bearer ${this.#accessToken}`);
    }
    return fetch(url, { ...options, headers });
  }

  async #handlePageLoad() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('sja_code');
    const err = params.get('sja_error');
    if (!code && !err) return;

    if (err) {
      this.#oAuthError = err;
      params.delete('sja_error');
    }
    if (code) {
      params.delete('sja_code');
    }
    const remaining = params.toString();
    const cleanUrl = window.location.pathname + (remaining ? `?${remaining}` : '') + window.location.hash;
    window.history.replaceState(null, '', cleanUrl);

    if (code) {
      try {
        await this.#exchangeOneTimeCode(code);
      } catch {
        this.#oAuthError = 'exchange_failed';
      }
    }
  }

  async #exchangeOneTimeCode(code) {
    const res = await fetch(`${this.#baseUrl}/oauth/exchange`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      },
      credentials: 'include',
      body: JSON.stringify({ code }),
    });
    if (!res.ok) {
      throw new AuthError('OAuth exchange failed', { status: res.status });
    }
    const { accessToken } = await res.json();
    this.#setAccessToken(accessToken);
  }

  #setAccessToken(token) {
    const changed = (this.#accessToken === null) !== (token === null);
    this.#accessToken = token;
    if (changed) {
      const loggedIn = token !== null;
      for (const fn of this.#listeners) {
        try { fn(loggedIn); } catch { /* isolate listeners */ }
      }
    }
  }
}

async function readBodySafely(res) {
  try { return await res.json(); }
  catch {
    try { return await res.text(); }
    catch { return null; }
  }
}
