package com.simplejwtauth.auth.application.service;

import com.simplejwtauth.auth.application.port.in.CheckSessionUseCase;
import com.simplejwtauth.auth.application.port.in.LogoutUseCase;
import com.simplejwtauth.auth.application.port.in.RefreshUseCase;
import com.simplejwtauth.auth.application.port.out.RefreshTokenStore;
import com.simplejwtauth.auth.domain.AuthToken;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SessionApplicationService implements RefreshUseCase, LogoutUseCase, CheckSessionUseCase {

    private final RefreshTokenStore refreshTokenStore;
    private final TokenIssuer tokenIssuer;

    @Override
    public AuthToken refresh(String refreshToken) {
        return tokenIssuer.rotateTokens(refreshToken);
    }

    @Override
    public void logout(String refreshToken) {
        refreshTokenStore.invalidate(refreshToken);
    }

    @Override
    public String currentUserId(String refreshToken) {
        return refreshTokenStore.findUserId(refreshToken);
    }
}
