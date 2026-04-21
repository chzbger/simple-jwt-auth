package com.simplejwtauth.common;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@ConfigurationProperties(prefix = "simple-jwt-auth")
@Validated
public record AuthProperties(
        @Valid @NotNull Jwt jwt,
        @Valid @DefaultValue Web web
) {

    public record Jwt(
            @NotBlank String secret,                                    // HS256 secret. UTF-8 32바이트 이상
            @DefaultValue("15m") Duration accessTokenExpiry,            // access token 유효 기간
            @DefaultValue("2h") Duration refreshTokenExpiry,            // refresh token 유효 기간
            @DefaultValue("2d") Duration sessionMaxLifetime,            // 세션 최대 시간(활동 중이라도 이 시간 지나면 재로그인)
            @DefaultValue("30s") Duration clockSkew                     // JWT exp 검증 시 허용 시계 오차
    ) {}

    public record Web(
            @DefaultValue("/api/auth") String basePath,
            @DefaultValue("sja_rt") String cookieName,
            @DefaultValue("true") Boolean cookieSecure,
            @DefaultValue("Strict") String cookieSameSite,
            @DefaultValue("/") String postLoginRedirect,
            @DefaultValue("/?sja_error=") String postLoginErrorRedirect
    ) {}
}
