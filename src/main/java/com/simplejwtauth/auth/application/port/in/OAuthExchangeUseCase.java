package com.simplejwtauth.auth.application.port.in;

public interface OAuthExchangeUseCase {
    /** sja_code 1회 소비 -> access token. invalid/만료 시 null */
    String exchange(String code);
}
