package com.simplejwtauth.common.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * SecurityContext 에서 userId 꺼내는 헬퍼
 */
public final class AuthContext {

    private AuthContext() {}

    // @Auth / @PreAuthorize 보호된 endpoint 면 호출 시점에 인증 가능
    public static String getUserId() {
        String userId = findUserId();
        if (userId == null) throw new IllegalStateException("인증된 사용자 없음");
        return userId;
    }

    public static String findUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) return null;
        Object principal = auth.getPrincipal();
        if (principal instanceof Jwt jwt) {
            return jwt.getSubject();
        }
        if (principal instanceof UserDetails ud) {
            return ud.getUsername();
        }
        if (principal instanceof String s && !"anonymousUser".equals(s)) {
            return s;
        }
        return null;
    }
}
