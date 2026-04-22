package com.simplejwtauth.auth.application.config;

public record OAuthGoogleSettings(
        String clientId,
        String clientSecret,
        String redirectUri
) {}
