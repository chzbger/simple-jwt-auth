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
  #userId = null;          // /me 로 확인된 사용자. access token 없을때도 채워질 수 있음
  #baseUrl;
  #listeners = new Set();
  #refreshPromise = null;
  #oAuthError = null;

  constructor({ baseUrl = '/api/auth', onAuthChange } = {}) {
    this.#baseUrl = baseUrl;
    if (typeof onAuthChange === 'function') this.addAuthListener(onAuthChange);
    if (typeof window !== 'undefined') {
      queueMicrotask(async () => {
        this.#handlePageLoad();              // ?sja_error=... 만 처리
        await this.#checkSession();          // cookie 로 logged-in 인지 확인
      });
    }
  }

  get isLoggedIn() {
    return this.#accessToken !== null || this.#userId !== null;
  }

  get userId() {
    return this.#userId;
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
      // network error
    }
    this.#clearAuth();
  }

  async fetch(url, options = {}) {
    let res = await this.#authFetch(url, options);

    // access token 보유 중 OR /me 로 세션 확인됨 -> 401 시 refresh 시도
    if (res.status === 401 && this.isLoggedIn) {
      const refreshed = await this.#refresh();
      if (refreshed) {
        res = await this.#authFetch(url, options);
      } else {
        this.#clearAuth();
      }
    }
    return res;
  }

  async #checkSession() {
    try {
      const res = await fetch(`${this.#baseUrl}/me`, {
        method: 'GET',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        credentials: 'include',
      });
      if (res.ok) {
        const { userId } = await res.json();
        this.#setUserId(userId);   // access token 없이도 logged-in 상태 알림
      }
    } catch {
      // network err
    }
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

  // OAuth redirect 직후 URL 의 ?sja_error=... 만 처리. 성공 시엔 URL 이 깨끗
  #handlePageLoad() {
    const params = new URLSearchParams(window.location.search);
    const err = params.get('sja_error');
    if (!err) return;

    this.#oAuthError = err;
    params.delete('sja_error');
    const remaining = params.toString();
    const cleanUrl = window.location.pathname + (remaining ? `?${remaining}` : '') + window.location.hash;
    window.history.replaceState(null, '', cleanUrl);
  }

  #setAccessToken(token) {
    const wasLoggedIn = this.isLoggedIn;
    this.#accessToken = token;
    this.#notifyIfChanged(wasLoggedIn);
  }

  #setUserId(userId) {
    const wasLoggedIn = this.isLoggedIn;
    this.#userId = userId;
    this.#notifyIfChanged(wasLoggedIn);
  }

  #clearAuth() {
    const wasLoggedIn = this.isLoggedIn;
    this.#accessToken = null;
    this.#userId = null;
    this.#notifyIfChanged(wasLoggedIn);
  }

  #notifyIfChanged(wasLoggedIn) {
    const isNow = this.isLoggedIn;
    if (wasLoggedIn !== isNow) {
      for (const fn of this.#listeners) {
        try { fn(isNow); } catch { /* isolate listeners */ }
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
