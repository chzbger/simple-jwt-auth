package com.simplejwtauth.auth.application.port.out;

public interface RefreshTokenStore {

    void issueToken(String plainToken, String userId);

    String rotate(String plainOldToken, String plainNewToken);

    void invalidate(String plainToken);
}
