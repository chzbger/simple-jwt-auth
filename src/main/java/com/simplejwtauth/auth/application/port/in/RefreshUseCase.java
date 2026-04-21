package com.simplejwtauth.auth.application.port.in;

import com.simplejwtauth.auth.domain.AuthToken;

public interface RefreshUseCase {
    AuthToken refresh(String refreshToken);
}
