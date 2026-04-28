package com.simplejwtauth.auth.application.port.out;

/**
 * 소비자 구현 SPI — provider 식별자를 내부 userId 로 매핑. OAuth/OIDC 성공 직후 1회 호출
 * registrationId: yml 의 spring.security.oauth2.client.registration.<id> 키 (google/naver/kakao 등)
 * providerId: OIDC 면 sub claim, plain OAuth2 면 OAuth2User.getName()
 */
public interface OAuthUserResolver {
    String resolve(String registrationId, String providerId);
}
