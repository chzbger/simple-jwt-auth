package com.simplejwtauth.auth.application.service;

import com.simplejwtauth.auth.application.port.in.LoginUseCase;
import com.simplejwtauth.auth.application.port.out.PasswordVerifier;
import com.simplejwtauth.auth.domain.AuthToken;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class LoginApplicationService implements LoginUseCase {

    private final PasswordVerifier passwordVerifier;
    private final TokenIssuer tokenIssuer;

    @Override
    public AuthToken login(String username, String password) {
        String userId = passwordVerifier.verify(username, password);
        return tokenIssuer.issueTokens(userId);
    }
}
