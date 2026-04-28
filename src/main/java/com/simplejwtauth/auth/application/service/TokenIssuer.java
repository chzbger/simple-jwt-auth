package com.simplejwtauth.auth.application.service;

import com.simplejwtauth.auth.application.config.JwtSettings;
import com.simplejwtauth.auth.application.port.out.RefreshTokenStore;
import com.simplejwtauth.auth.domain.AuthToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class TokenIssuer {

    private final JwtEncoder jwtEncoder;
    private final JwtSettings jwtSettings;
    private final RefreshTokenStore refreshTokenStore;

    /**
     * 새 세션 (로컬 로그인 / OAuth 성공) 시 호출.
     * 단일 디바이스 (id:token 1:1)
     */
    public AuthToken issueTokens(String userId) {
        String newRefreshToken = newRefreshToken();
        refreshTokenStore.issueToken(newRefreshToken, userId);
        return new AuthToken(createAccessToken(userId), newRefreshToken);
    }

    /**
     * Refresh token 회전. 옛 토큰이 무효/만료된 경우 throw 401
     */
    public AuthToken rotateTokens(String oldRefreshToken) {
        String newRefreshToken = newRefreshToken();
        String userId = refreshTokenStore.rotate(oldRefreshToken, newRefreshToken);
        if (userId == null) {
            throw new IllegalArgumentException("유효하지 않은 refresh token");
        }
        return new AuthToken(createAccessToken(userId), newRefreshToken);
    }

    private String createAccessToken(String userId) {
        Instant now = Instant.now();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(userId)
                .issuedAt(now)
                .expiresAt(now.plus(jwtSettings.accessTokenExpiry()))
                .build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    private static String newRefreshToken() {
        return UUID.randomUUID().toString();
    }
}
