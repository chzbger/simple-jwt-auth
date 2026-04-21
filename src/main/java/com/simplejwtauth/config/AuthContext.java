package com.simplejwtauth.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Optional;

public final class AuthContext {

    static final String ATTR_KEY = "AUTH_USER_ID";

    private AuthContext() {}

    public static void set(HttpServletRequest request, Long userId) {
        request.setAttribute(ATTR_KEY, userId);
    }

    /**
     * Returns the authenticated user's id.
     *
     * @throws IllegalStateException when called outside a request thread or when the current request
     *                               is not protected by {@code @Auth} (no authenticated user bound).
     */
    public static Long getUserId() {
        return getOptionalUserId().orElseThrow(() -> new IllegalStateException(
                "No authenticated user in request context. Ensure the endpoint is annotated with @Auth."));
    }

    public static Optional<Long> getOptionalUserId() {
        var attrs = RequestContextHolder.getRequestAttributes();
        if (!(attrs instanceof ServletRequestAttributes sra)) return Optional.empty();
        Object value = sra.getRequest().getAttribute(ATTR_KEY);
        return value instanceof Long userId ? Optional.of(userId) : Optional.empty();
    }
}
