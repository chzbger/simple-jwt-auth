# simple-jwt-auth

쉽게 사용 가능한 JWT 인증 라이브러리. 

## 요약

- dependency 추가하고, 로그인 관련 간단한 구현(DB 연동)하면 jwt토큰과 oauth 등을 간단하게 사용 가능
- 단일 세션만 가능(한 사용자는 한 번에 한 활성 refresh 세션만 가질 수 있음)
- 인증정보 관리는 embedded Hazelcast IMap으로 관리 
- AccessToken(JWT) / RefreshToken(UUID cookie)
- jwt 기본 15분, refresh rotate는 기본 2시간, 최대 시간은 기본 2일 후엔 만료

## API

| Method | Path | Request | Response |
|---|---|---|---|
| POST | `${base-path}/login` | `{"username":"...","password":"..."}` | `{"accessToken":"..."}` + Set-Cookie |
| POST | `${base-path}/refresh` | (cookie) | `{"accessToken":"..."}` + Set-Cookie |
| GET  | `${base-path}/me` | (cookie) | `{"userId":"..."}` |
| POST | `${base-path}/logout` | (cookie) | 200 OK |
| GET  | `${base-path}/oauth/{provider}` | path: `provider` | 302 → provider 로그인 페이지 |
| GET  | `${base-path}/oauth/callback/{provider}` | query: `code`, `state` | 302 → post-login-redirect |

* 에러 응답 401/403 은 ProblemDetail:

```json
{
  "type": "...",
  "title": "Unauthorized",
  "status": 401,
  "detail": "...",
  "instance": "/api/..."
}
```

## 프론트엔드 샘플 js

샘플로 만든 `/sja/auth.js` 로 사용 가능.

```javascript
import { SimpleJwtAuth } from '/sja/auth.js';

// 인스턴스 생성. 페이지 로드 시 /me 자동 호출 → cookie 살아있으면 로그인 복원
const auth = new SimpleJwtAuth();

// 로컬 로그인 (실패 시 AuthError throw)
await auth.login('alice', 'password');

// Google 로그인 (전체 페이지 redirect)
auth.loginWithGoogle();

// API 호출 (401 실패시엔 refresh후 재시도)
await auth.fetch('/api/posts', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ title: 'Hello' }),
});

// 로그아웃 (서버 refresh 무효화 + 로컬 access token 제거)
await auth.logout();

auth.isLoggedIn;   // boolean
auth.userId;       // 로그인 시 userId, 아니면 null
```

## 사용법

### 1. dependency 추가

[![](https://jitpack.io/v/chzbger/simple-jwt-auth.svg)](https://jitpack.io/#chzbger/simple-jwt-auth)

JitPack 사용. consumer 의 build 설정에 jitpack repository 와 dependency 추가:

Gradle:
```groovy
repositories {
    mavenCentral()
    maven { url 'https://jitpack.io' }
}

dependencies {
    implementation 'com.github.chzbger:simple-jwt-auth:1.0.0'
}
```

Maven:
```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<dependency>
    <groupId>com.github.chzbger</groupId>
    <artifactId>simple-jwt-auth</artifactId>
    <version>1.0.0</version>
</dependency>
```

### 2. application.yml 설정값 추가

```yaml
simple-jwt-auth:
  jwt:
    secret: "${AUTH_JWT_SECRET}" # 필수. UTF-8 32바이트 이상 (HS256)
    access-token-expiry: 15m
    refresh-token-expiry: 2h
    session-max-lifetime: 2d
    clock-skew: 30s
  web:
    base-path: /api/auth
    cookie-name: sja_rt
    cookie-secure: true
    cookie-same-site: Strict
    post-login-redirect: /
    post-login-error-redirect: /?sja_error=

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

### 3. 백엔드 구현 필요

#### 3.0 사용자 테이블 (예시)

```sql
CREATE TABLE users (
    id            BIGINT       PRIMARY KEY AUTO_INCREMENT,
    username      VARCHAR(64)  UNIQUE,        -- 로컬 로그인 ID (OAuth 전용이면 NULL)
    password_hash VARCHAR(72),                 -- BCrypt 해시 (OAuth 전용이면 NULL)
    provider      VARCHAR(32),                 -- 'google' | 'naver' | 'kakao' ... (로컬 전용이면 NULL)
    provider_id   VARCHAR(255),                -- OAuth sub claim (로컬 전용이면 NULL)
    email         VARCHAR(255),
    created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uk_provider (provider, provider_id)
);
```
- 로컬 전용: `username` + `password_hash` set, `provider` / `provider_id` NULL
- OAuth 전용: `provider` + `provider_id` set, `username` / `password_hash` NULL

#### 3.1 `UserDetailsService` (로컬 로그인 시)(필수)

```java
@Service
@RequiredArgsConstructor
public class MyUserDetailsService implements UserDetailsService {
    private final UserRepository users;

    @Override
    public UserDetails loadUserByUsername(String username) {
        User u = users.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Not found: " + username));
        return org.springframework.security.core.userdetails.User
                .withUsername(String.valueOf(u.getId()))
                .password(u.getPasswordHash())
                .authorities(u.getRoles())
                .build();
    }
}
```

#### 3.2 `OAuthUserResolver` (OAuth 사용 시)(선택)

```java
@Component
@RequiredArgsConstructor
public class MyOAuthUserResolver implements OAuthUserResolver {
    private final UserRepository users;

    @Override
    public String resolve(String registrationId, String providerId) {
        return users.findByProviderAndProviderId(registrationId, providerId)
                .map(User::getId)
                .orElseGet(() -> users.save(new User(registrationId, providerId)).getId())
                .toString();
    }
}
```

#### 3.3 `@Auth` 어노테이션

```java
public class PostController {
    @Auth
    @PostMapping("/api/posts")
    public Post create(@RequestBody CreatePostRequest req) {...}
}

@Auth
@RestController
public class UserController { ... }
```

#### 3.4 `AuthContext.getUserId()`

현재 요청의 인증된 userId 반환. security endpoint 에서만 있음.

```java
String userId = AuthContext.getUserId();
```

## 빌드

```bash
./gradlew build       # 컴파일 + 테스트 (JUnit 5, 20개)
```
