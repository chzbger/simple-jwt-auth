package com.simplejwtauth.adapter.in.web;

import com.simplejwtauth.application.config.WebSettings;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;

import java.time.Duration;

public class CookieHelper {

    private final WebSettings web;
    private final long refreshTokenMaxAge;

    public CookieHelper(WebSettings web, Duration refreshTokenExpiry) {
        this.web = web;
        this.refreshTokenMaxAge = refreshTokenExpiry.toSeconds();
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
