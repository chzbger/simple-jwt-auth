# simple-jwt-auth

DB 없이 동작하는 JWT 인증 라이브러리. Spring Boot 3.5 / Spring Security 6.5 / Java 21 기반.

디펜던시로 추가하면 로컬 로그인 / OAuth(OIDC) / 로그아웃 / 토큰 회전이 바로 동작한다.

## 핵심 기능

- 로컬 username + password 로그인 (JSON body)
- OAuth 2.1 / OIDC 소비 (Google 등) — Spring Security 표준 흐름 (PKCE/state/nonce/JWKS 자동 처리)
- 단순 Refresh Token Rotation
- **단일 세션 정책** — 새 로그인이 들어오면 기존 세션은 즉시 종료 (멀티 디바이스 동시 로그인 미지원). 1:1 IMap 의 atomic put-replace 가 schema 레벨에서 강제
- **Absolute session lifetime 캡** — 회전을 거쳐도 최초 로그인 시각을 보존, 설정한 최대 시간이 지나면 회전 실패. 기본 2일
- OAuth 콜백 후 **one-time code (sja_code) 교환** — access token 이 URL/히스토리/Referer 에 안 남음
- Hazelcast 임베디드 (별도 인프라 0)
- `@Auth` 어노테이션 (= `@PreAuthorize("isAuthenticated()")` 메타-어노테이션) + `AuthContext.getUserId()`
- Plain JavaScript 프론트엔드 SDK (`auth.js`) JAR 번들

> **단일 세션 정책 주의**: 한 사용자는 한 번에 한 활성 refresh 세션만 가질 수 있다.
> 사용자가 PC 에서 로그인 후 모바일에서 다시 로그인하면 PC 세션은 즉시 종료된다.
> 멀티 디바이스 동시 로그인이 필요한 서비스 (Gmail/Netflix 류) 에는 부적합.
> 단일 세션 강제 시 부수 효과: **재로그인이 곧 "전체 토큰 폐기"** 라서 탈취된 refresh token 도 재로그인 시 함께 무효화된다.

## 사용법

### 1. 의존성

```groovy
implementation 'com.simplejwtauth:simple-jwt-auth:1.0.0'
```

라이브러리가 가져오는 것: `spring-boot-starter-security`, `spring-boot-starter-oauth2-client`, `spring-boot-starter-oauth2-resource-server`, `hazelcast-spring`. 소비자는 추가 의존성 없이 starter 한 줄로 시작.

JAR 에 프론트엔드 SDK (`auth.js`) 가 번들되어 Spring Boot 가 `/sja/auth.js` 로 자동 서빙.

### 2. application.yml

```yaml
simple-jwt-auth:
  jwt:
    secret: "${AUTH_JWT_SECRET}"             # 필수. UTF-8 32바이트 이상 (HS256)
    access-token-expiry: 15m                  # 기본
    refresh-token-expiry: 2h                  # 기본 (idle 한계 — 회전 사이 sliding window)
    session-max-lifetime: 2d                  # 기본 (절대 한계 — 활동 중이라도 이 시간 지나면 재로그인)
    clock-skew: 30s                           # 기본
  web:
    base-path: /api/auth                      # 기본
    cookie-name: sja_rt                       # 기본
    cookie-secure: true                       # 기본 (로컬 http 테스트 시 false)
    cookie-same-site: Strict                  # 기본
    post-login-redirect: /                    # OAuth 성공 후 redirect 대상
    post-login-error-redirect: /?sja_error=

# OAuth provider 설정은 Spring Security 표준 위치
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: "${GOOGLE_CLIENT_ID}"
            client-secret: "${GOOGLE_CLIENT_SECRET}"
            scope: openid, email
            redirect-uri: "{baseUrl}/api/auth/oauth/callback/{registrationId}"
```

OAuth provider 추가 (Naver, Kakao, GitHub 등) 는 yml 에 한 블록 더 — 코드 수정 0.

### 3. SPI 구현

**로컬 로그인**: Spring Security 표준 `UserDetailsService`

```java
@Service
@RequiredArgsConstructor
public class MyUserDetailsService implements UserDetailsService {
    private final UserRepository users;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User u = users.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Not found: " + username));
        return org.springframework.security.core.userdetails.User
                .withUsername(String.valueOf(u.getId()))   // JWT sub 으로 들어감
                .password(u.getPasswordHash())              // 라이브러리 BCryptPasswordEncoder 가 비교
                .authorities(u.getRoles())                  // 또는 Collections.emptyList()
                .build();
    }
}
```

라이브러리가 `BCryptPasswordEncoder` 빈을 기본 제공. 다른 알고리즘 원하면 `@Bean PasswordEncoder` 로 override.

**OAuth (Google 등)**: 우리 단일 SPI `OAuthUserResolver`

```java
@Component
@RequiredArgsConstructor
public class MyOAuthUserResolver implements OAuthUserResolver {
    private final UserRepository users;

    @Override
    public String resolve(String registrationId, String providerId) {
        // registrationId == yml 의 "google" / "naver" / ...
        // providerId    == OIDC sub claim (Google) 또는 OAuth2User.getName()
        return users.findByProviderAndProviderId(registrationId, providerId)
                .map(User::getId)
                .orElseGet(() -> users.save(new User(registrationId, providerId)).getId())
                .toString();
    }
}
```

둘 다 구현하면 둘 다 활성. 로컬 로그인만 — `UserDetailsService` 만. OAuth 만 — `OAuthUserResolver` + yml 만.

### 4. `@Auth` 와 인증 정책

`@Auth` 는 Spring Security 의 `@PreAuthorize("isAuthenticated()")` 메타-어노테이션. 메서드/클래스에 모두 부착 가능.

```java
import com.simplejwtauth.auth.adapter.in.web.annotation.Auth;
import com.simplejwtauth.common.security.AuthContext;

@RestController
public class PostController {
    @GetMapping("/api/posts")                                     // 공개
    public List<Post> list() { return postService.findAll(); }

    @Auth                                                         // 인증 필요
    @PostMapping("/api/posts")
    public Post create(@RequestBody CreatePostRequest req) {
        String userId = AuthContext.getUserId();                  // JWT sub 원본 (String)
        return postService.create(Long.valueOf(userId), req);     // 소비자가 타입 변환
    }
}

// 클래스 전체 보호
@Auth
@RestController
@RequestMapping("/api/users")
public class UserController { ... }
```

더 강한 표현은 Spring Security 표준 그대로:

```java
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
@DeleteMapping("/api/posts/{id}")
public void delete(...) { ... }

@PreAuthorize("#userId == authentication.principal.subject")
@GetMapping("/api/users/{userId}/profile")
public Profile profile(@PathVariable String userId) { ... }
```

`AuthContext.getUserId()` 는 보호된 endpoint 에선 항상 인증 보장 → 직접 사용. 비보호 endpoint 에선 `getOptionalUserId()`.

### 5. Default-deny 모드 (옵션)

라이브러리는 기본 `anyRequest().permitAll()` + `@Auth` 가 붙은 메서드만 보호. **default-deny 로 가려면 자체 `SecurityFilterChain` 빈 등록** — 라이브러리 default 가 자동 비활성:

```java
@Configuration
public class CustomSecurityConfig {
    @Bean
    SecurityFilterChain customFilterChain(HttpSecurity http, /* 라이브러리 빈들 inject */) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(STATELESS))
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/api/auth/**", "/sja/**", "/actuator/**").permitAll()
                        .anyRequest().authenticated()             // 명시 보호 안 한 건 다 막음
                )
                .oauth2ResourceServer(rs -> rs.jwt(...))
                /* ... 라이브러리 SecurityConfig 참조 */
                .build();
    }
}
```

### 6. 프론트엔드

UI 는 소비 프로젝트가 직접. SDK 는 토큰/세션만 관리. `auth.js` 가 라이브러리 JAR 에 번들되어 자동으로 `/sja/auth.js` 로 서빙됨.

```html
<form id="login-form">
  <input name="username" autocomplete="username" required />
  <input name="password" type="password" autocomplete="current-password" required />
  <button type="submit">로그인</button>
</form>
<button id="google">Google 로그인</button>

<script type="module">
  import { SimpleJwtAuth } from '/sja/auth.js';

  const auth = new SimpleJwtAuth();                               // OAuth 콜백 자동 처리
  auth.addAuthListener(loggedIn => console.log('logged in?', loggedIn));

  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    await auth.login(f.get('username'), f.get('password'));
  });
  document.getElementById('google').addEventListener('click', () => auth.loginWithGoogle());

  const res = await auth.fetch('/api/posts');                     // 401 시 자동 refresh 1회
</script>
```

#### SDK API

| 멤버 | 설명 |
|---|---|
| `new SimpleJwtAuth({ baseUrl? })` | `baseUrl` 기본 `/api/auth` |
| `.login(username, password)` | JSON body 로 POST. 실패 시 `AuthError` |
| `.loginWithGoogle()` | `/api/auth/oauth/google` 으로 전체 redirect |
| `.logout()` | 서버 측 refresh token 무효화 + 로컬 access token 제거 |
| `.fetch(url, options)` | 401 발생 시 refresh 1회 후 재시도 |
| `.addAuthListener(fn)` | 로그인 상태 변경 리스너 등록, 해제 함수 반환 |
| `.isLoggedIn` | getter |
| `.lastOAuthError` | OAuth redirect 로 전달된 에러 코드 (1회 읽으면 소멸) |

- Access token: **JS 메모리에만** 보관 (XSS 시에도 refresh 못 탈취)
- Refresh token: **httpOnly cookie**, JS 접근 불가
- 동시 401 발생해도 `#refreshPromise` 로 in-flight refresh 메모이즈 → rotation 1회만
- OAuth 콜백 URL 의 `?sja_code=` 는 exchange 직후 `history.replaceState` 로 제거

## 인증 흐름

### 로컬 로그인

```
POST /api/auth/login {username, password}
  → JsonAuthenticationFilter             [라이브러리]
  → AuthenticationManager → UserDetailsService.loadUserByUsername()  [소비자 SPI]
  → BCryptPasswordEncoder.matches()      [라이브러리, 또는 소비자 override]
  → LocalLoginSuccessHandler             [라이브러리]
    → TokenIssuer.issueTokens(userId)
    → userToToken IMap 의 1:1 put-replace 가 직전 hash 자동 무효화 (단일 세션 정책)
    → Access Token (JWT HS256, 15m, body)
    → Refresh Token (UUID, 2h sliding cookie / 2d absolute cap)
```

### Google 로그인 (one-time code 교환)

```
GET  /api/auth/oauth/google
  → Spring Security OAuth2AuthorizationRequestRedirectFilter
  → state + PKCE code_challenge 자동 생성, Hazelcast 에 임시 저장 (10m TTL)
  → Google 로그인 페이지 redirect

GET  /api/auth/oauth/callback/google
  → Spring Security OAuth2LoginAuthenticationFilter
  → state 검증 + code 교환 + ID token JWKS 검증 (Spring 자동)
  → OAuth2LoginSuccessHandler          [라이브러리]
    → OAuthUserResolver.resolve(registrationId, sub)  [소비자 SPI]
    → TokenIssuer.issueTokens(userId)  → 기존 세션 자동 무효화 + 새 토큰 (sessionStartedAt = now)
    → Refresh cookie 발급
    → sja_code 발급 (60s TTL)
    → 302 {post-login-redirect}?sja_code=<code>

POST /api/auth/oauth/exchange {code}
  → OAuthController → OAuthExchangeUseCase → OAuthCodeStore.consume(code)
  → {accessToken} 반환 (code 1회 소멸)
```

프론트는 URL 의 `sja_code` 를 파싱 → `/api/auth/oauth/exchange` 로 교환 → access token 메모리 저장 → URL 정리. **access token 이 URL/히스토리/Referer 에 안 남는다.**

### Refresh Token Rotation

```
Access 만료 → POST /api/auth/refresh (cookie 자동 전송)
  → SessionApplicationService.refresh()
  → tokenToUser.remove(hash(oldToken))  [Hazelcast IMap atomic remove]
    → null 이면: 401 반환 (이미 회전됐거나 만료)
  → userToToken.remove(userId) → 직전 RefreshEntry 꺼냄
    → now - sessionStartedAt > session-max-lifetime → 401 (절대 한계 초과 → 재로그인 강제)
    → 성공: 새 hash 로 entry 갱신, sessionStartedAt 보존, refresh-token-expiry TTL 리셋
```

이미 회전된 옛 refresh token 은 다음 시도에 401. 절대 한계 (`session-max-lifetime`) 도 회전마다 검사 — 회전이 cap 을 우회 못 함.

### Logout

```
POST /api/auth/logout
  → Spring Security LogoutFilter
  → RefreshTokenLogoutHandler            [라이브러리]
    → cookie 의 refresh token 무효화
    → cookie 만료
  → 200 OK
```

## API 엔드포인트

| Method | Path | 활성 조건 | 설명 |
|---|---|---|---|
| POST | `${base-path}/login` | `UserDetailsService` 빈 존재 | 로컬 로그인 |
| POST | `${base-path}/refresh` | 항상 | Access 재발급 (refresh 회전) |
| POST | `${base-path}/logout` | 항상 | Refresh token 무효화 + cookie 만료 |
| GET | `${base-path}/oauth/{provider}` | yml registration + `OAuthUserResolver` 빈 | OAuth 시작 (Spring Security) |
| GET | `${base-path}/oauth/callback/{provider}` | 위와 동일 | OAuth 콜백 (Spring Security) |
| POST | `${base-path}/oauth/exchange` | 위와 동일 | `{code}` → `{accessToken}` |

401/403 응답 body: `{"error":"<reason_code>","message":"..."}`. 모든 토큰 응답에 `Cache-Control: no-store`.

## 토큰 저장 방식

| 토큰/상태 | 저장 위치 | 이유 |
|---|---|---|
| Access Token | 클라이언트 JS 메모리 | XSS 로 탈취돼도 refresh 안전 |
| Refresh Token | httpOnly + Secure + SameSite=Strict 쿠키 (path=`${base-path}`) | JS 접근 불가, CSRF 방어 |
| Refresh hash | Hazelcast IMap (`rt-token-user`) — `sha256(token) → userId` | TTL 자동 만료 |
| User → entry | Hazelcast IMap (`rt-user-token`) — `userId → RefreshEntry(hash, sessionStartedAt)` 1:1. atomic put-replace 가 단일 세션 강제, sessionStartedAt 이 absolute lifetime cap | TTL 자동 만료 |
| OAuth flow state | Hazelcast IMap (`oauth-authz-request`), 10m TTL — Spring Security `AuthorizationRequestRepository` |
| OAuth one-time code | Hazelcast IMap (`oauth-code`), 60s TTL, 1회 소멸 |
| Google JWKS | Spring Security 가 `JwtDecoder` 내부에서 자동 캐시 + rotation |

## 보안 사항

- **단일 세션 정책 (schema 강제)**: `userId → RefreshEntry` 1:1 IMap 의 atomic put-replace 가 직전 active hash 를 자동 무효화. 탈취된 refresh token 도 사용자 재로그인 시 함께 죽음
- **Absolute session lifetime**: 회전 시에도 `sessionStartedAt` 보존 → `session-max-lifetime` (기본 2일) 초과 시 강제 재로그인. 탈취자가 회전을 반복해도 cap 우회 불가
- **PKCE / state / nonce / JWKS rotation**: Spring Security OAuth2 Client 가 자동 — 수동 구현 0
- **OAuth access token URL 노출**: `sja_code` 1회용 교환으로 차단. URL/히스토리/Referer 어디에도 access token 없음
- **JWT 검증**: NimbusJwtDecoder + `JwtTimestampValidator(clockSkew)` — clock skew 설정 가능 (기본 30s)
- **Stateless**: `SessionCreationPolicy.STATELESS` — HTTP session 0. OAuth flow 임시 데이터도 Hazelcast (session 안 씀)
- **CSRF**: bearer JWT 패턴이라 CSRF 비활성. cookie path 는 `${base-path}` 로 한정 + `SameSite=Strict`
- **쿠키**: httpOnly + Secure (기본) + SameSite=Strict + path=base-path
- **Refresh token 평문 저장 금지**: SHA-256 해시만 store 에 저장
- **`Cache-Control: no-store`**: 모든 토큰 반환 응답에 적용 (OAuth 2.1 §4.1.4)
- **JWT secret 길이 검증**: UTF-8 32바이트 미만이면 startup 시점에 fail-fast

### 명시적 비-기능

- **Multi-device 동시 로그인 미지원** (단일 세션 정책)
- **Refresh token reuse detection (family CAS)** 미적용 — 의도된 단순화. 탈취된 refresh token 은 자연 만료 또는 사용자 재로그인 시까지 살아있음
- **DPoP / mTLS sender-constrained tokens 미지원**
- **Token introspection / revocation endpoint (RFC 7662/7009) 미제공**

## 빌드 & 배포

```bash
./gradlew build       # simple-jwt-auth-1.0.0.jar 생성 (bootJar 비활성, plain jar)
```

JAR 에 `META-INF/spring-configuration-metadata.json` (IDE 자동완성), `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` (auto-config 등록), `META-INF/resources/sja/auth.js` (프론트 SDK) 포함.

## 아키텍처

헥사고날 (Ports & Adapters) + Spring Security 표준 흐름 위에 단일 세션 / sja_code / 프론트 SDK 가 얹힌 형태.

```
com.simplejwtauth
├── auth/                                 # 헥사고날 hexagon
│   ├── domain/                           AuthToken
│   ├── application/
│   │   ├── config/                       JwtSettings, WebSettings (POJO records)
│   │   ├── port/in/                      RefreshUseCase, LogoutUseCase, OAuthExchangeUseCase
│   │   ├── port/out/                     RefreshTokenStore, OAuthCodeStore,
│   │   │                                 OAuthUserResolver  ← 소비자 SPI
│   │   └── service/                      TokenIssuer, SessionApplicationService, OAuthExchangeService
│   └── adapter/
│       ├── in/web/                       SessionController (refresh),
│       │                                 OAuthController (sja_code exchange),
│       │                                 CookieHelper, @Auth annotation, dto/
│       └── out/hazelcast/                HazelcastRefreshTokenStore,
│                                         HazelcastOAuthCodeStore,
│                                         HazelcastAuthorizationRequestRepository
└── common/
    ├── AuthAutoConfiguration             @AutoConfiguration — Hazelcast/JwtEncoder/JwtDecoder/store 빈
    ├── AuthProperties                    @ConfigurationProperties
    └── security/                         Spring Security framework 통합
        ├── SecurityConfig                @Configuration — SecurityFilterChain
        ├── AuthContext                   현재 요청의 인증 사용자 id (소비자 호출)
        ├── JsonAuthenticationFilter
        ├── LocalLoginSuccessHandler / LocalLoginFailureHandler
        ├── OAuth2LoginSuccessHandler / OAuth2LoginFailureHandler
        ├── RefreshTokenLogoutHandler
        ├── JsonAuthenticationEntryPoint  (401)
        └── JsonAccessDeniedHandler        (403)
```

소비자가 `UserDetailsService` 만 구현하면 **로컬 로그인만** 활성. yml 에 OAuth registration + `OAuthUserResolver` 만 — OAuth 만 활성. 둘 다 — 둘 다 활성. 아무것도 안 — `/refresh` 와 `/logout` 만 노출 (토큰 관리).
