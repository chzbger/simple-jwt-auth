/**
 * simple-jwt-auth frontend module
 *
 * Usage:
 *   import { SimpleJwtAuth } from './auth.js';
 *   const auth = new SimpleJwtAuth({ baseUrl: '/api/auth' });
 *
 *   await auth.ready();              // 초기 세션 복원 끝까지 대기
 *   auth.addAuthListener(loggedIn => console.log('logged in?', loggedIn));
 *
 *   await auth.login('user@example.com', 'password');
 *   auth.loginWithGoogle();
 *   const res = await auth.fetch('/api/posts');   // 401 시 자동 refresh + 1회 retry
 *   const token = await auth.getAccessToken();    // WebSocket 등 fetch 외 transport 용
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
  #initialized = false;
  #readyPromise;

  constructor({ baseUrl = '/api/auth', onAuthChange } = {}) {
    this.#baseUrl = baseUrl;
    if (typeof onAuthChange === 'function') this.addAuthListener(onAuthChange);
    this.#readyPromise = this.#initialRestore();
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

  /**
   * 초기 세션 복원 (?sja_error= 처리 + GET /me) 이 끝날 때까지 대기.
   * SPA 첫 렌더 직전에 한 번 await 하는 용도.
   */
  ready() {
    return this.#readyPromise;
  }

  /**
   * 현재 access token 반환. 메모리에 없는데 logged-in 상태면 자동 refresh.
   * fetch 외 transport (WebSocket/SSE 등) 에서 사용.
   */
  async getAccessToken() {
    if (this.#accessToken) return this.#accessToken;
    if (this.isLoggedIn) await this.#refresh();
    return this.#accessToken;
  }

  /**
   * 인증 상태 변경 시 호출. fn(isLoggedIn).
   * - 초기 restore 완료 직후 1회 호출됨
   * - restore 완료 후 등록 시 다음 microtask 에 현재 상태 1회 호출
   * @returns 등록 해제 함수
   */
  addAuthListener(fn) {
    this.#listeners.add(fn);
    if (this.#initialized) {
      queueMicrotask(() => {
        if (this.#listeners.has(fn)) {
          try { fn(this.isLoggedIn); } catch { /* isolate */ }
        }
      });
    }
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

  async #initialRestore() {
    // 생성자 동기 종료 보장 (consumer 가 listener 등록할 시간 확보)
    await Promise.resolve();
    if (typeof window !== 'undefined') {
      try {
        this.#handlePageLoad();
        await this.#checkSession();
      } catch {
        // 초기 복원 실패는 anonymous 로 진행, 절대 throw 하지 않음
      }
    }
    this.#initialized = true;
    this.#notifyAll();
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
    if (wasLoggedIn !== isNow) this.#notifyAll();
  }

  #notifyAll() {
    for (const fn of this.#listeners) {
      try { fn(this.isLoggedIn); } catch { /* isolate listeners */ }
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
