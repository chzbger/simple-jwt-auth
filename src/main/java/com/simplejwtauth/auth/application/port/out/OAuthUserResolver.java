package com.simplejwtauth.auth.application.port.out;

/**
 * OAuth 사용시 구현 필수
 */
public interface OAuthUserResolver {
    String resolve(String registrationId, String providerId);
}
