package com.simplejwtauth.application.service;

import com.simplejwtauth.application.config.JwtSettings;
import com.simplejwtauth.application.exception.InvalidTokenException;
import com.simplejwtauth.application.port.in.AccessTokenValidator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

public class JwtProvider implements AccessTokenValidator {

    private final SecretKey key;
    private final JwtSettings jwtSettings;

    public JwtProvider(JwtSettings jwtSettings) {
        this.jwtSettings = jwtSettings;
        this.key = Keys.hmacShaKeyFor(jwtSettings.secret().getBytes(StandardCharsets.UTF_8));
    }

    public String createAccessToken(Long userId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(String.valueOf(userId))
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(jwtSettings.accessTokenExpiry())))
                .signWith(key)
                .compact();
    }

    public String createRefreshToken() {
        return UUID.randomUUID().toString();
    }

    @Override
    public Long validateAndGetUserId(String token) {
        Claims claims;
        try {
            claims = Jwts.parser()
                    .verifyWith(key)
                    .clockSkewSeconds(jwtSettings.clockSkew().toSeconds())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new InvalidTokenException(InvalidTokenException.Reason.EXPIRED, "Token expired", e);
        } catch (SignatureException e) {
            throw new InvalidTokenException(InvalidTokenException.Reason.SIGNATURE, "Invalid signature", e);
        } catch (MalformedJwtException | IllegalArgumentException e) {
            throw new InvalidTokenException(InvalidTokenException.Reason.MALFORMED, "Malformed token", e);
        } catch (RuntimeException e) {
            throw new InvalidTokenException(InvalidTokenException.Reason.INVALID, "Invalid token", e);
        }

        String sub = claims.getSubject();
        if (sub == null || sub.isBlank()) {
            throw new InvalidTokenException(InvalidTokenException.Reason.MALFORMED, "Token missing subject");
        }
        try {
            return Long.valueOf(sub);
        } catch (NumberFormatException e) {
            throw new InvalidTokenException(InvalidTokenException.Reason.MALFORMED, "Token subject not numeric", e);
        }
    }
}
