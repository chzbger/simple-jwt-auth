package com.simplejwtauth.common;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.List;

@ConfigurationProperties(prefix = "simple-jwt-auth")
@Validated
public record AuthProperties(
        Boolean enabled,
        @Valid @NotNull Jwt jwt,
        @Valid Web web,
        @Valid Security security,
        @Valid OAuth oauth
) {

    public AuthProperties {
        if (enabled == null) enabled = Boolean.TRUE;
        if (web == null) web = new Web(null, null, null, null, null, null);
        if (security == null) security = new Security(null, null);
        if (oauth == null) oauth = new OAuth(null);
    }

    public record Jwt(
            @NotBlank String secret,
            Duration accessTokenExpiry,
            Duration refreshTokenExpiry,
            Duration clockSkew
    ) {
        public Jwt {
            if (accessTokenExpiry == null) accessTokenExpiry = Duration.ofMinutes(15);
            if (refreshTokenExpiry == null) refreshTokenExpiry = Duration.ofMinutes(30);
            if (clockSkew == null) clockSkew = Duration.ofSeconds(30);
            if (accessTokenExpiry.isNegative() || accessTokenExpiry.isZero())
                throw new IllegalArgumentException("simple-jwt-auth.jwt.access-token-expiry must be positive");
            if (refreshTokenExpiry.isNegative() || refreshTokenExpiry.isZero())
                throw new IllegalArgumentException("simple-jwt-auth.jwt.refresh-token-expiry must be positive");
            if (clockSkew.isNegative())
                throw new IllegalArgumentException("simple-jwt-auth.jwt.clock-skew must be >= 0");
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

    public record Security(Policy defaultPolicy, List<String> publicPaths) {

        public Security {
            if (defaultPolicy == null) defaultPolicy = Policy.ALLOW;
            publicPaths = publicPaths == null ? List.of() : List.copyOf(publicPaths);
        }

        public enum Policy { ALLOW, DENY }
    }

    public record OAuth(@Valid Google google) {

        public record Google(
                String clientId,
                String clientSecret,
                String redirectUri
        ) {}
    }
}
