package com.simplejwtauth.auth.application.config;

public record WebSettings(
        String basePath,
        String cookieName,
        boolean cookieSecure,
        String cookieSameSite,
        String postLoginRedirect,
        String postLoginErrorRedirect
) {}
