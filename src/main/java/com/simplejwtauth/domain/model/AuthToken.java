package com.simplejwtauth.domain.model;

public record AuthToken(
        String accessToken,
        String refreshToken
) {}
