package com.simplejwtauth.common;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.simplejwtauth.auth.adapter.in.web.annotation.Auth;
import com.simplejwtauth.auth.application.config.SecuritySettings;
import com.simplejwtauth.auth.application.error.InvalidTokenException;
import com.simplejwtauth.auth.application.port.in.AccessTokenValidator;
import com.simplejwtauth.auth.domain.AuthContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class AuthInterceptor implements HandlerInterceptor {

    private final AccessTokenValidator accessTokenValidator;
    private final ObjectMapper objectMapper;
    private final SecuritySettings security;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws IOException {
        if (!(handler instanceof HandlerMethod method)) {
            return true;
        }

        if (!authRequired(method, lookupPath(request))) {
            return true;
        }

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            sendUnauthorized(response, "missing_token", "Missing or invalid Authorization header");
            return false;
        }

        try {
            String token = header.substring(7);
            String userId = accessTokenValidator.validateAndGetUserId(token);
            AuthContext.set(request, userId);
            return true;
        } catch (InvalidTokenException e) {
            sendUnauthorized(response, e.getType().name().toLowerCase(), e.getMessage());
            return false;
        }
    }

    /**
     * Method-level {@code @Auth} → class-level {@code @Auth} → global policy (+ public-paths) 순으로 해석.
     * {@code path}는 servlet context 경로 기준.
     */
    public boolean authRequired(HandlerMethod method, String path) {
        Auth methodAuth = method.getMethodAnnotation(Auth.class);
        if (methodAuth != null) return methodAuth.isAuth();

        Auth classAuth = method.getBeanType().getAnnotation(Auth.class);
        if (classAuth != null) return classAuth.isAuth();

        if (security.defaultPolicy() == SecuritySettings.Policy.ALLOW) {
            return false;
        }
        if (path != null) {
            for (String pattern : security.publicPaths()) {
                if (pathMatcher.match(pattern, path)) return false;
            }
        }
        return true;
    }

    private static String lookupPath(HttpServletRequest request) {
        String servletPath = request.getServletPath();
        if (servletPath == null || servletPath.isEmpty()) {
            String uri = request.getRequestURI();
            String ctx = request.getContextPath();
            return (ctx != null && !ctx.isEmpty() && uri.startsWith(ctx)) ? uri.substring(ctx.length()) : uri;
        }
        return servletPath;
    }

    private void sendUnauthorized(HttpServletResponse response, String code, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=UTF-8");
        try {
            response.getWriter().write(objectMapper.writeValueAsString(Map.of(
                    "error", code,
                    "message", message
            )));
        } catch (JsonProcessingException e) {
            response.getWriter().write("{\"error\":\"" + code + "\"}");
        }
    }
}
