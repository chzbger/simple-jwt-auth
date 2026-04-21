package com.simplejwtauth.auth.adapter.in.web;

import com.simplejwtauth.auth.application.config.JwtSettings;
import com.simplejwtauth.auth.application.config.WebSettings;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieHelper {

    private final WebSettings web;
    private final long refreshTokenMaxAge;

    public CookieHelper(WebSettings web, JwtSettings jwt) {
        this.web = web;
        this.refreshTokenMaxAge = jwt.refreshTokenExpiry().toSeconds();
    }

    public void setRefreshCookie(HttpServletResponse response, String refreshToken) {
        ResponseCookie cookie = buildCookie(refreshToken, refreshTokenMaxAge);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    public void clearRefreshCookie(HttpServletResponse response) {
        ResponseCookie cookie = buildCookie("", 0);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private ResponseCookie buildCookie(String value, long maxAge) {
        return ResponseCookie.from(web.cookieName(), value)
                .httpOnly(true)
                .secure(web.cookieSecure())
                .path(web.basePath())
                .maxAge(maxAge)
                .sameSite(web.cookieSameSite())
                .build();
    }
}
