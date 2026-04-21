package com.simplejwtauth.application.config;

public record OAuthGoogleSettings(
        String clientId,
        String clientSecret,
        String redirectUri
) {}
