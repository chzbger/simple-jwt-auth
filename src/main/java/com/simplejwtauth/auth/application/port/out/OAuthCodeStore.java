package com.simplejwtauth.auth.application.port.out;

import java.util.Optional;

public interface OAuthCodeStore {

    // access token 에 묶인 1회용 opaque code 발급
    String issue(String accessToken);

    // code 에 묶인 access token 을 원자적으로 조회+무효화
    String consume(String code);
}
