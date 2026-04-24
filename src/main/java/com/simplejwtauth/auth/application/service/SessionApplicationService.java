package com.simplejwtauth.auth.application.service;

import com.simplejwtauth.auth.application.port.in.LogoutUseCase;
import com.simplejwtauth.auth.application.port.in.RefreshUseCase;
import com.simplejwtauth.auth.application.port.out.RefreshTokenStore;
import com.simplejwtauth.auth.domain.AuthToken;
import com.simplejwtauth.auth.domain.TokenFamily;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SessionApplicationService implements RefreshUseCase, LogoutUseCase {

    private final RefreshTokenStore refreshTokenStore;
    private final TokenIssuer tokenIssuer;

    @Override
    public AuthToken refresh(String refreshToken) {
        TokenFamily family = refreshTokenStore.lookup(refreshToken)
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));
        return tokenIssuer.rotateTokens(family, refreshToken);
    }

    @Override
    public void logout(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) return;
        refreshTokenStore.lookup(refreshToken)
                .ifPresent(family -> refreshTokenStore.invalidateFamily(family.familyId()));
    }
}
