package com.simplejwtauth.application.service;

import com.simplejwtauth.application.port.in.LogoutUseCase;
import com.simplejwtauth.application.port.in.RefreshUseCase;
import com.simplejwtauth.application.port.out.RefreshTokenStore;
import com.simplejwtauth.domain.model.AuthToken;
import com.simplejwtauth.domain.model.TokenFamily;

public class SessionApplicationService implements RefreshUseCase, LogoutUseCase {

    private final RefreshTokenStore refreshTokenStore;
    private final TokenIssuer tokenIssuer;

    public SessionApplicationService(RefreshTokenStore refreshTokenStore, TokenIssuer tokenIssuer) {
        this.refreshTokenStore = refreshTokenStore;
        this.tokenIssuer = tokenIssuer;
    }

    @Override
    public AuthToken refresh(String refreshToken) {
        String hash = Sha256Hasher.hash(refreshToken);
        TokenFamily family = refreshTokenStore.lookup(hash)
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));
        return tokenIssuer.rotateTokens(family, hash);
    }

    @Override
    public void logout(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) return;
        String hash = Sha256Hasher.hash(refreshToken);
        refreshTokenStore.lookup(hash)
                .ifPresent(family -> refreshTokenStore.invalidateFamily(family.familyId()));
    }
}
