package com.simplejwtauth.application.service;

import com.simplejwtauth.application.port.in.LoginUseCase;
import com.simplejwtauth.application.port.out.PasswordVerifier;
import com.simplejwtauth.domain.model.AuthToken;

public class LoginApplicationService implements LoginUseCase {

    private final PasswordVerifier passwordVerifier;
    private final TokenIssuer tokenIssuer;

    public LoginApplicationService(PasswordVerifier passwordVerifier, TokenIssuer tokenIssuer) {
        this.passwordVerifier = passwordVerifier;
        this.tokenIssuer = tokenIssuer;
    }

    @Override
    public AuthToken login(String username, String password) {
        Long userId = passwordVerifier.verify(username, password);
        return tokenIssuer.issueTokens(userId);
    }
}
