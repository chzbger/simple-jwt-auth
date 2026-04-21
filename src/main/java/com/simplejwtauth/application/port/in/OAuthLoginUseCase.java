package com.simplejwtauth.application.port.in;

import com.simplejwtauth.domain.model.OAuthProvider;

public interface OAuthLoginUseCase {

    String getAuthorizationUrl(OAuthProvider provider);

    /**
     * Validates {@code state}, exchanges {@code code} with the provider, and issues a session.
     * Returns the refresh token (to be put in an httpOnly cookie) and a short-lived one-time
     * code the client uses to retrieve the access token via {@link #consumeOneTimeCode(String)}.
     *
     * @throws IllegalArgumentException if state is missing / not previously issued (CSRF).
     */
    OAuthCallbackResult handleCallback(OAuthProvider provider, String code, String state);

    /** Consume the one-time code returned via redirect; returns the access token or empty if invalid/expired. */
    String consumeOneTimeCode(String oneTimeCode);

    record OAuthCallbackResult(String oneTimeCode, String refreshToken) {}
}
