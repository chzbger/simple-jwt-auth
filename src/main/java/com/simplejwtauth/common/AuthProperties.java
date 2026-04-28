package com.simplejwtauth.common;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * 라이브러리 설정. OAuth provider 설정은 spring.security.oauth2.client.registration.* 에 위치
 */
@ConfigurationProperties(prefix = "simple-jwt-auth")
@Validated
public record AuthProperties(
        Boolean enabled,
        @Valid @NotNull Jwt jwt,
        @Valid Web web
) {

    public AuthProperties {
        if (enabled == null) enabled = Boolean.TRUE;
        if (web == null) web = new Web(null, null, null, null, null, null);
    }

    public record Jwt(
            @NotBlank String secret,
            Duration accessTokenExpiry,
            Duration refreshTokenExpiry,
            Duration sessionMaxLifetime,
            Duration clockSkew
    ) {
        public Jwt {
            if (accessTokenExpiry == null) accessTokenExpiry = Duration.ofMinutes(15);
            if (refreshTokenExpiry == null) refreshTokenExpiry = Duration.ofHours(2);
            if (sessionMaxLifetime == null) sessionMaxLifetime = Duration.ofDays(2);
            if (clockSkew == null) clockSkew = Duration.ofSeconds(30);
            // HS256 은 32바이트(256비트) 이상의 secret 을 요구 — fail-fast 로 미리 검증
            if (secret != null && secret.getBytes(java.nio.charset.StandardCharsets.UTF_8).length < 32)
                throw new IllegalArgumentException(
                        "simple-jwt-auth.jwt.secret 은 UTF-8 기준 32바이트(256비트) 이상이어야 합니다");
            if (accessTokenExpiry.isNegative() || accessTokenExpiry.isZero())
                throw new IllegalArgumentException("simple-jwt-auth.jwt.access-token-expiry 는 양수여야 합니다");
            if (refreshTokenExpiry.isNegative() || refreshTokenExpiry.isZero())
                throw new IllegalArgumentException("simple-jwt-auth.jwt.refresh-token-expiry 는 양수여야 합니다");
            if (sessionMaxLifetime.isNegative() || sessionMaxLifetime.isZero())
                throw new IllegalArgumentException("simple-jwt-auth.jwt.session-max-lifetime 는 양수여야 합니다");
            if (clockSkew.isNegative())
                throw new IllegalArgumentException("simple-jwt-auth.jwt.clock-skew 는 0 이상이어야 합니다");
        }
    }

    public record Web(
            String basePath,
            String cookieName,
            Boolean cookieSecure,
            String cookieSameSite,
            String postLoginRedirect,
            String postLoginErrorRedirect
    ) {
        public Web {
            if (basePath == null || basePath.isBlank()) basePath = "/api/auth";
            if (cookieName == null || cookieName.isBlank()) cookieName = "sja_rt";
            if (cookieSecure == null) cookieSecure = Boolean.TRUE;
            if (cookieSameSite == null || cookieSameSite.isBlank()) cookieSameSite = "Strict";
            if (postLoginRedirect == null || postLoginRedirect.isBlank()) postLoginRedirect = "/";
            if (postLoginErrorRedirect == null || postLoginErrorRedirect.isBlank())
                postLoginErrorRedirect = "/?sja_error=";
        }
    }
}
