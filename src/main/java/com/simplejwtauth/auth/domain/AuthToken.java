package com.simplejwtauth.auth.domain;

public record AuthToken(
        String accessToken,
        String refreshToken
) {}
