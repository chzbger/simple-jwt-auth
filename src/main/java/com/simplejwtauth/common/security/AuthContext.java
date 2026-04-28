package com.simplejwtauth.common.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Optional;

/**
 * SecurityContext 에서 userId 꺼내는 헬퍼
 * principal: Jwt(sub) / UserDetails(username) / String 순으로 분기
 */
public final class AuthContext {

    private AuthContext() {}

    // @Auth / @PreAuthorize 보호된 endpoint 면 호출 시점에 항상 인증 보장됨, 아니면 throw
    public static String getUserId() {
        return getOptionalUserId().orElseThrow(() -> new IllegalStateException(
                "현재 요청에 인증된 사용자가 없습니다. @Auth 등으로 보호된 endpoint 인지 확인하세요."));
    }

    public static Optional<String> getOptionalUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) return Optional.empty();
        Object principal = auth.getPrincipal();
        if (principal instanceof Jwt jwt) {
            return Optional.ofNullable(jwt.getSubject());
        }
        if (principal instanceof UserDetails ud) {
            return Optional.ofNullable(ud.getUsername());
        }
        if (principal instanceof String s && !"anonymousUser".equals(s)) {
            return Optional.of(s);
        }
        return Optional.empty();
    }
}
