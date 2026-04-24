package com.simplejwtauth.auth.application.service;

import com.simplejwtauth.auth.application.config.JwtSettings;
import com.simplejwtauth.auth.application.error.InvalidTokenException;
import com.simplejwtauth.auth.application.port.in.AccessTokenValidator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtProvider implements AccessTokenValidator {

    private final SecretKey key;
    private final JwtSettings jwtSettings;
    public static final InvalidTokenException EXPIRED_EX = new InvalidTokenException(InvalidTokenException.Type.EXPIRED);
    public static final InvalidTokenException INVALID_EX = new InvalidTokenException(InvalidTokenException.Type.INVALID);

    public JwtProvider(JwtSettings jwtSettings) {
        this.jwtSettings = jwtSettings;
        this.key = Keys.hmacShaKeyFor(jwtSettings.secret().getBytes(StandardCharsets.UTF_8));
    }

    public String createAccessToken(String userId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(userId)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(jwtSettings.accessTokenExpiry())))
                .signWith(key)
                .compact();
    }

    public String createRefreshToken() {
        return UUID.randomUUID().toString();
    }

    @Override
    public String validateAndGetUserId(String token) {
        Claims claims;
        try {
            claims = Jwts.parser()
                    .verifyWith(key)
                    .clockSkewSeconds(jwtSettings.clockSkew().toSeconds())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw EXPIRED_EX;
        } catch (Exception e) {
            throw INVALID_EX;
        }

        String sub = claims.getSubject();
        if (sub == null || sub.isBlank()) {
            throw INVALID_EX;
        }
        return sub;
    }
}
