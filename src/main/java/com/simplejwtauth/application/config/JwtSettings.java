package com.simplejwtauth.application.config;

import java.time.Duration;

public record JwtSettings(
        String secret,
        Duration accessTokenExpiry,
        Duration refreshTokenExpiry,
        Duration clockSkew
) {}
