package com.simplejwtauth.application.service;

import com.simplejwtauth.application.port.in.OAuthLoginUseCase;
import com.simplejwtauth.application.port.out.OAuthClient;
import com.simplejwtauth.application.port.out.OAuthCodeStore;
import com.simplejwtauth.application.port.out.OAuthStateStore;
import com.simplejwtauth.application.port.out.OAuthUserResolver;
import com.simplejwtauth.domain.model.AuthToken;
import com.simplejwtauth.domain.model.OAuthProvider;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

public class OAuthApplicationService implements OAuthLoginUseCase {

    private static final Duration STATE_TTL = Duration.ofMinutes(10);
    private static final Duration CODE_TTL = Duration.ofSeconds(60);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final OAuthUserResolver oAuthUserResolver;
    private final Map<OAuthProvider, OAuthClient> clients;
    private final OAuthStateStore stateStore;
    private final OAuthCodeStore codeStore;
    private final TokenIssuer tokenIssuer;

    public OAuthApplicationService(OAuthUserResolver oAuthUserResolver,
                                   Map<OAuthProvider, OAuthClient> clients,
                                   OAuthStateStore stateStore,
                                   OAuthCodeStore codeStore,
                                   TokenIssuer tokenIssuer) {
        this.oAuthUserResolver = oAuthUserResolver;
        this.clients = clients;
        this.stateStore = stateStore;
        this.codeStore = codeStore;
        this.tokenIssuer = tokenIssuer;
    }

    @Override
    public String getAuthorizationUrl(OAuthProvider provider) {
        String state = newRandomToken();
        stateStore.store(state, STATE_TTL);
        return clientFor(provider).getAuthorizationUrl(state);
    }

    @Override
    public OAuthCallbackResult handleCallback(OAuthProvider provider, String code, String state) {
        if (!stateStore.consume(state)) {
            throw new IllegalArgumentException("Invalid or expired OAuth state");
        }
        String providerId = clientFor(provider).exchangeCodeForProviderId(code);
        Long userId = oAuthUserResolver.resolve(provider, providerId);
        AuthToken tokens = tokenIssuer.issueTokens(userId);
        String oneTimeCode = codeStore.issue(tokens.accessToken(), CODE_TTL);
        return new OAuthCallbackResult(oneTimeCode, tokens.refreshToken());
    }

    @Override
    public String consumeOneTimeCode(String oneTimeCode) {
        return codeStore.consume(oneTimeCode)
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired one-time code"));
    }

    private OAuthClient clientFor(OAuthProvider provider) {
        OAuthClient client = clients.get(provider);
        if (client == null) {
            throw new IllegalArgumentException("Unsupported OAuth provider: " + provider);
        }
        return client;
    }

    private static String newRandomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
