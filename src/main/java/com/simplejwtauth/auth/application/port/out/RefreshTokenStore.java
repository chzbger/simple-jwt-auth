package com.simplejwtauth.auth.application.port.out;

public interface RefreshTokenStore {

    void issueToken(String plainToken, String userId);

    RotateResult rotate(String plainOldToken, String plainNewToken);

    void invalidate(String plainToken);

    String findUserId(String plainToken);

    sealed interface RotateResult {
        record Success(String userId) implements RotateResult {}
        record Invalid() implements RotateResult {}            // 토큰이 store 에 없음 (이미 회전/만료)
        record SessionExpired() implements RotateResult {}     // absolute session lifetime 초과
    }
}
