package com.simplejwtauth.auth.application.config;

import java.time.Duration;

public record JwtSettings(
        String secret,
        Duration accessTokenExpiry,
        Duration refreshTokenExpiry,
        Duration sessionMaxLifetime,
        Duration clockSkew
) {}
