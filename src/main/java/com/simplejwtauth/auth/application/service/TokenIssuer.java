package com.simplejwtauth.auth.application.service;

import com.simplejwtauth.auth.application.config.JwtSettings;
import com.simplejwtauth.auth.application.port.out.RefreshTokenStore;
import com.simplejwtauth.auth.domain.AuthToken;
import com.simplejwtauth.auth.domain.TokenFamily;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class TokenIssuer {

    private final JwtProvider jwtProvider;
    private final RefreshTokenStore refreshTokenStore;
    private final JwtSettings jwtSettings;

    /** Issues tokens for a brand-new session (login / OAuth first-time), starts a new family. */
    public AuthToken issueTokens(String userId) {
        String refreshToken = jwtProvider.createRefreshToken();
        String familyId = UUID.randomUUID().toString();
        refreshTokenStore.issueFamily(
                RefreshTokenStore.Sha256Hasher.hash(refreshToken),
                userId,
                familyId,
                jwtSettings.refreshTokenExpiry()
        );
        return new AuthToken(jwtProvider.createAccessToken(userId), refreshToken);
    }

    /**
     * Rotates within an existing family. Throws if the CAS fails (reuse/replay detected),
     * which also invalidates every token in the family.
     */
    public AuthToken rotateTokens(TokenFamily family, String oldHash) {
        String newRefresh = jwtProvider.createRefreshToken();
        String newHash = RefreshTokenStore.Sha256Hasher.hash(newRefresh);
        boolean ok = refreshTokenStore.rotate(
                family.familyId(), oldHash, newHash, jwtSettings.refreshTokenExpiry()
        );
        if (!ok) {
            refreshTokenStore.invalidateFamily(family.familyId());
            throw new IllegalStateException("Refresh token reuse detected; family revoked");
        }
        return new AuthToken(jwtProvider.createAccessToken(family.userId()), newRefresh);
    }
}
