package com.simplejwtauth.auth.application.service;

import com.simplejwtauth.auth.application.port.in.OAuthLoginUseCase;
import com.simplejwtauth.auth.application.port.out.OAuthClient;
import com.simplejwtauth.auth.application.port.out.OAuthCodeStore;
import com.simplejwtauth.auth.application.port.out.OAuthStateStore;
import com.simplejwtauth.auth.application.port.out.OAuthUserResolver;
import com.simplejwtauth.auth.domain.AuthToken;
import com.simplejwtauth.auth.domain.OAuthProvider;
import lombok.RequiredArgsConstructor;

import java.security.SecureRandom;
import java.util.Base64;

@RequiredArgsConstructor
public class OAuthApplicationService implements OAuthLoginUseCase {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final OAuthUserResolver oAuthUserResolver;
    private final OAuthClient oAuthClient;
    private final OAuthStateStore stateStore;
    private final OAuthCodeStore codeStore;
    private final TokenIssuer tokenIssuer;

    @Override
    public String getAuthorizationUrl(OAuthProvider provider) {
        String state = newRandomToken();
        stateStore.store(state);
        return oAuthClient.getAuthorizationUrl(provider, state);
    }

    @Override
    public OAuthCallbackResult handleCallback(OAuthProvider provider, String code, String state) {
        if (!stateStore.consume(state)) {
            throw new IllegalArgumentException("Invalid or expired OAuth state");
        }
        String providerId = oAuthClient.exchangeCodeForProviderId(provider, code);
        String userId = oAuthUserResolver.resolve(provider, providerId);
        AuthToken tokens = tokenIssuer.issueTokens(userId);
        String oneTimeCode = codeStore.issue(tokens.accessToken());
        return new OAuthCallbackResult(oneTimeCode, tokens.refreshToken());
    }

    @Override
    public String consumeOneTimeCode(String oneTimeCode) {
        return codeStore.consume(oneTimeCode)
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired one-time code"));
    }

    private static String newRandomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
