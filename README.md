# simple-jwt-auth

DB 없이 동작하는 JWT 인증 라이브러리. Spring Boot 3.5.13 / Java 21 기반.

디펜던시로 추가하면 로그인 / OAuth / 로그아웃 / 토큰 관리가 바로 동작한다.

## 지원 기능

- 일반 로그인 (username + password)
- Google OAuth 2.0 (OIDC) — **state CSRF 방어 + ID token JWKS 서명 검증**
- Sliding Refresh Token Rotation — **family 기반 atomic CAS + reuse detection** (OAuth 2.1 §6.1)
- Hazelcast 임베디드 (별도 인프라 불필요)
- `@Auth` 어노테이션 + `AuthContext.getUserId()`
- OAuth 콜백은 **one-time code 교환** (프론트 URL에 access token 노출 X)
- Plain JavaScript 프론트엔드 (프레임워크 무관, 접근성/동시성 대응)

## 사용법

### 1. 디펜던시

```groovy
// build.gradle (consumer)
implementation 'com.simplejwtauth:simple-jwt-auth:1.0.0'
```

JAR 안에 프론트엔드 SDK(`auth.js`)가 같이 번들되어 Spring Boot가 자동으로 `/sja/auth.js` 경로로 서빙한다. **디펜던시 한 줄 추가만으로 백엔드 인증 엔드포인트 + 프론트엔드 SDK 모두 사용 가능.**

### 2. application.yml

```yaml
simple-jwt-auth:
  # enabled: true                    # 기본값. false로 두면 빈 전혀 안 뜸
  jwt:
    secret: "${AUTH_JWT_SECRET}"     # 필수. 32바이트 이상 (HS256)
    access-token-expiry: 15m         # 기본
    refresh-token-expiry: 30m        # 기본
    clock-skew: 30s                  # 기본
  web:
    base-path: /api/auth                 # 기본
    cookie-name: sja_rt          # 기본
    cookie-secure: true              # 기본 (로컬 http 테스트 시 false)
    cookie-same-site: Strict         # 기본
    post-login-redirect: /           # OAuth 성공 후 리다이렉트 대상
    post-login-error-redirect: /?sja_error=
  security:                          # 선택
    default-policy: allow            # 기본. deny로 두면 어노테이션 없는 경로 전부 보호
    public-paths: []                 # deny 모드에서 예외 경로 (Ant 패턴)
  oauth:                             # OAuth 사용 시에만 필수
    google:
      client-id: "${GOOGLE_CLIENT_ID}"
      client-secret: "${GOOGLE_CLIENT_SECRET}"
      redirect-uri: "${GOOGLE_REDIRECT_URI}"
```

### 3. 포트 구현

**local login 만 사용하는 경우**:

```java
@Component
public class MyPasswordVerifier implements PasswordVerifier {
    private final UserRepository users;
    private final PasswordEncoder encoder;
    // ...
    @Override
    public Long verify(String username, String password) {
        User user = users.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));
        if (!encoder.matches(password, user.getPasswordHash()))
            throw new IllegalArgumentException("Invalid credentials");
        return user.getId();
    }
}
```

**OAuth 만 사용하는 경우** — `PasswordVerifier` 없이 `OAuthUserResolver`만 구현:

```java
@Component
public class MyOAuthUserResolver implements OAuthUserResolver {
    private final UserRepository users;
    // ...
    @Override
    public Long resolve(OAuthProvider provider, String providerId) {
        return users.findByProviderAndProviderId(provider.name(), providerId)
                .map(User::getId)
                .orElseGet(() -> users.save(new User(provider.name(), providerId)).getId());
    }
}
```

둘 다 구현하면 둘 다 활성화. 아무것도 구현하지 않으면 `/api/auth/refresh`, `/api/auth/logout`만 노출 (토큰 관리).

### 4. `@Auth` 와 인증 정책

`@Auth` 는 메서드/클래스에 붙일 수 있으며, 메서드 레벨이 클래스 레벨보다 우선한다.

```java
@RestController
public class PostController {
    @GetMapping("/api/posts")
    public List<Post> list() { return postService.findAll(); }              // 공개

    @Auth
    @PostMapping("/api/posts")
    public Post create(@RequestBody CreatePostRequest req) {
        Long userId = AuthContext.getUserId();                              // 인증된 유저
        return postService.create(userId, req);
    }
}

// 클래스 전체 보호 + 일부 메서드만 예외로 공개
@Auth
@RestController
@RequestMapping("/api/users")
public class UserController {
    @GetMapping("/{id}")     public User get(...)     { ... }               // 보호
    @PutMapping("/{id}")     public User update(...)  { ... }               // 보호

    @Auth(isAuth = false)
    @GetMapping("/public-profile/{handle}")
    public PublicProfile publicProfile(...) { ... }                         // 예외
}
```

`AuthContext.getUserId()`는 `@Auth` 밖에서 호출 시 `IllegalStateException`. 선택적 확인은 `AuthContext.getOptionalUserId()`.

#### default-policy (옵션)

기본 정책은 `allow` — 어노테이션이 없는 엔드포인트는 공개. 이를 뒤집고 싶으면 `deny` 로 설정:

```yaml
simple-jwt-auth:
  security:
    default-policy: deny          # 기본 allow
    public-paths:                 # deny 모드에서 예외 (AntPathMatcher)
      - /actuator/**
      - /error
      - /favicon.ico
```

`deny` 모드 의미:
- 어노테이션 없는 엔드포인트 = **보호**
- `@Auth(isAuth = false)` 또는 `public-paths` 매칭 = 예외 공개
- 라이브러리 자체 엔드포인트(`/api/auth/login`, `/api/auth/refresh`, …)는 내부적으로 `@Auth(isAuth = false)` 표시되어 있어 별도 설정 불필요

#### 정책 감사 로그

기동 시 `simple-jwt-auth` 로거가 요약을 INFO로, 엔드포인트 분류 목록을 DEBUG로 출력한다:

```
[simple-jwt-auth] policy=ALLOW publicPaths=[] protected=3 public=9
```

DEBUG 레벨 활성화 시 각 엔드포인트가 `[PROTECTED]`/`[PUBLIC]`로 분류되어 출력되므로 배포 전 감사에 유용.

### 5. 프론트엔드

UI는 소비 프로젝트가 직접 그리고, 이 SDK는 토큰/세션만 관리한다. `auth.js`는 **라이브러리 JAR에 번들되어 자동으로 `/sja/auth.js` 로 서빙**되므로 별도 빌드/복사 없이 import하면 된다.

#### 순수 HTML

```html
<form id="login-form">
  <input name="username" autocomplete="username" required />
  <input name="password" type="password" autocomplete="current-password" required />
  <button type="submit">로그인</button>
</form>
<button id="google">Google 로그인</button>

<script type="module">
  import { SimpleJwtAuth } from '/sja/auth.js';                 // 라이브러리가 자동 서빙

  const auth = new SimpleJwtAuth();                             // OAuth 콜백 자동 처리
  auth.addAuthListener(loggedIn => console.log('logged in?', loggedIn));

  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    await auth.login(f.get('username'), f.get('password'));
  });
  document.getElementById('google').addEventListener('click', () => auth.loginWithGoogle());

  const res = await auth.fetch('/api/posts');                   // 401 시 자동 refresh 1회
</script>
```

#### React / Vue / Svelte (번들러 사용 시)

빌드 타임 import 경로로 `/sja/auth.js`는 못 쓴다 (바벨/번들러가 못 찾음). 두 가지 방법:

**(A) 런타임 dynamic import** — 가장 간단:

```js
const { SimpleJwtAuth } = await import(/* @vite-ignore */ '/sja/auth.js');
export const auth = new SimpleJwtAuth();
```

**(B) `<script type="module">` 로 먼저 로드하고 window 공유**:

```html
<!-- index.html -->
<script type="module">
  import { SimpleJwtAuth } from '/sja/auth.js';
  window.__sja = new SimpleJwtAuth();
</script>
```
```js
// 어느 컴포넌트에서든
const auth = window.__sja;
```

React hook 래퍼 예시:

```jsx
import { useEffect, useState } from 'react';

let auth = null;
async function getAuth() {
  if (!auth) {
    const { SimpleJwtAuth } = await import(/* @vite-ignore */ '/sja/auth.js');
    auth = new SimpleJwtAuth();
  }
  return auth;
}

export function useAuth() {
  const [loggedIn, setLoggedIn] = useState(false);
  useEffect(() => {
    let unsub;
    getAuth().then(a => {
      setLoggedIn(a.isLoggedIn);
      unsub = a.addAuthListener(setLoggedIn);
    });
    return () => unsub?.();
  }, []);
  return { loggedIn, auth: getAuth };
}
```

> Dev 서버가 백엔드와 분리된 경우 (Vite → Spring Boot) `/sja/auth.js` 요청을 백엔드로 프록시하도록 `vite.config.js`의 `server.proxy` 설정 필요.

### SDK API

| 멤버 | 설명 |
|---|---|
| `new SimpleJwtAuth({ baseUrl? })` | `baseUrl` 기본 `/api/auth` |
| `.login(username, password)` | 실패 시 `AuthError` (status, body 포함) |
| `.loginWithGoogle()` | `/api/auth/oauth/google` 로 전체 리다이렉트 |
| `.logout()` | 서버 측 family 무효화 + 로컬 access token 제거 |
| `.fetch(url, options)` | 401 발생 시 refresh 1회 후 재시도 |
| `.addAuthListener(fn)` | 로그인 상태 변경 리스너 등록, 해제 함수 반환 |
| `.isLoggedIn` | getter |
| `.lastOAuthError` | OAuth redirect로 전달된 에러 코드 (1회 읽으면 소멸) |

- Access token은 **JS 메모리에만** 보관 (XSS 시에도 refresh 못 탈취)
- Refresh token은 **httpOnly cookie**, JS가 접근 불가
- 동시 401 발생해도 `#refreshPromise`로 in-flight refresh 메모이즈 → rotation 한 번만
- OAuth 콜백 URL에 남은 `?sja_code=` 은 exchange 직후 `history.replaceState`로 제거, `search`/`pathname`/`hash` 보존

## 인증 흐름

### 일반 로그인

```
POST /api/auth/login {username, password}
  → PasswordVerifier.verify()            [소비 프로젝트 구현]
  → Access Token (15m, body)
  → Refresh Token (30m, httpOnly cookie, family 발급)
```

### Google 로그인 (one-time code 교환)

```
GET  /api/auth/oauth/google                  → 서버가 state 발급 (Hazelcast 10m TTL)
                                           → Google 로그인 페이지 redirect
GET  /api/auth/oauth/google/callback     → state consume + code 교환 + ID token 검증(JWKS)
                                           → OAuthUserResolver.resolve()
                                           → Refresh cookie + sja_code(60s) 발급
                                           → 302 {post-login-redirect}?sja_code=<code>
POST /api/auth/oauth/exchange {code}         → {accessToken} 반환 (code consume)
```

프론트는 URL의 `sja_code`를 파싱 → `/api/auth/oauth/exchange`로 교환 → access token을 메모리에 저장 → URL 정리. access token이 **URL/히스토리/Referer에 남지 않는다.**

### Sliding Refresh (family-based, reuse detection 포함)

```
Access 만료 → POST /api/auth/refresh (cookie 자동 전송)
  → familyCurrent.replace(familyId, oldHash, newHash) CAS
  → 성공: 새 Access + 새 Refresh (TTL 리셋)
  → 실패: 탈취/재사용 감지 → family 전체 무효화
```

## API 엔드포인트

| Method | Path | 조건 | 설명 |
|--------|------|------|------|
| POST | `${base-path}/login` | `PasswordVerifier` bean 존재 | 일반 로그인 |
| POST | `${base-path}/refresh` | 항상 | Access 재발급 (cookie의 refresh로 CAS 회전) |
| POST | `${base-path}/logout` | 항상 | Refresh family 무효화 |
| GET | `${base-path}/oauth/google` | `OAuthUserResolver` bean 존재 | state 발급 + Google 리다이렉트 |
| GET | `${base-path}/oauth/google/callback` | 위와 동일 | state 검증 + ID token 검증 + one-time code 발급 |
| POST | `${base-path}/oauth/exchange` | 위와 동일 | `{code}` → `{accessToken}` |

401/에러 응답 body는 `{"error":"<reason_code>","message":"..."}`.

## 토큰 저장 방식

| 토큰 | 저장 위치 | 이유 |
|------|-----------|------|
| Access Token | 클라이언트 JS 메모리 | XSS로 탈취되어도 refresh 안전 |
| Refresh Token | httpOnly + Secure + SameSite=Strict 쿠키 (path=`${base-path}`) | JS 접근 불가, CSRF 방어 |
| Refresh hash | Hazelcast (서버) — `{hash → family}` / `{family → currentHash}` | TTL 자동 만료, CAS rotation |
| OAuth state | Hazelcast, 10m TTL, 1-time consume | CSRF |
| OAuth one-time code | Hazelcast, 60s TTL, 1-time consume | URL 노출 방지 |
| Google JWKS | Hazelcast, 1h TTL | 서명 검증 키 캐시 |

## 보안 사항

- **Refresh 재사용 감지**: family 기반 `IMap.replace(fam, old, new)` atomic CAS. 실패 시 family 전체 무효화.
- **OAuth state CSRF**: authorize 시 `SecureRandom` 32바이트 base64url → store. callback에서 1-time consume.
- **Google ID token**: JWKS (kid 기반 RSA key) 서명 검증 + `iss` ∈ {`https://accounts.google.com`, `accounts.google.com`} + `aud == clientId` + `exp` (+30s clock skew).
- **OAuth access token 전달**: URL fragment 제거. 1회용 code 교환으로 대체.
- **JWT clock skew**: 설정 가능 (기본 30s).
- **AuthInterceptor 401**: `InvalidTokenException` 타입 분기 (EXPIRED/SIGNATURE/MALFORMED). ObjectMapper로 안전 직렬화.
- **CSRF 보조**: 프론트 모든 state-changing 요청에 `X-Requested-With: XMLHttpRequest` (preflight 강제).
- **쿠키**: httpOnly, Secure 기본 on, SameSite=Strict. path는 base-path와 일치. 이름은 기본 `sja_rt`.
- **Default deny 모드**: `simple-jwt-auth.security.default-policy: deny` 로 secure-by-default 전환 가능. 까먹은 `@Auth` = 노출 리스크를 제거하고 싶을 때 사용.

## 빌드 & 배포

```bash
gradle build               # simple-jwt-auth-1.0.0.jar 생성 (bootJar 비활성, plain jar)
```

JAR에는 `META-INF/spring-configuration-metadata.json` (IDE 자동완성) 과 `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` (auto-config 등록) 포함. `application.yml`은 **라이브러리 JAR에 포함되지 않는다** — 소비 프로젝트가 직접 설정.

## 아키텍처

헥사고날 (Ports & Adapters). `application` 레이어는 Spring 프레임워크 무의존.

```
com.simplejwtauth
├── domain/model/                   AuthToken, OAuthProvider, TokenFamily
├── application/
│   ├── config/                     JwtSettings, WebSettings, OAuthGoogleSettings (내부 POJO)
│   ├── exception/                  InvalidTokenException
│   ├── port/in/                    LoginUseCase, OAuthLoginUseCase, RefreshUseCase, LogoutUseCase, AccessTokenValidator
│   ├── port/out/
│   │   ├── PasswordVerifier        ← 소비 프로젝트 구현 (local login 사용 시)
│   │   ├── OAuthUserResolver       ← 소비 프로젝트 구현 (OAuth 사용 시)
│   │   ├── RefreshTokenStore       (Hazelcast 구현 내장)
│   │   ├── OAuthClient             (Google 구현 내장)
│   │   ├── OAuthStateStore         (Hazelcast 구현 내장)
│   │   ├── OAuthCodeStore          (Hazelcast 구현 내장)
│   │   └── JwksProvider            (Google JWKS, Hazelcast 캐시 내장)
│   └── service/                    JwtProvider, TokenIssuer,
│                                   LoginApplicationService, OAuthApplicationService, SessionApplicationService
├── adapter/
│   ├── in/web/                     LoginController, SessionController, OAuthController, AuthInterceptor, CookieHelper
│   └── out/
│       ├── hazelcast/              HazelcastRefreshTokenStore, HazelcastOAuthStateStore, HazelcastOAuthCodeStore
│       └── google/                 GoogleOAuthClient, HazelcastCachedGoogleJwksProvider
└── config/                         AuthAutoConfiguration, AuthProperties, WebMvcConfig,
                                    Auth, AuthContext
```

소비 프로젝트가 `PasswordVerifier` 만 구현하면 **local login 만** 활성화되고 OAuth 관련 빈은 아예 뜨지 않는다 (`@ConditionalOnBean` 게이팅). `OAuthUserResolver`만 구현하면 그 반대.
