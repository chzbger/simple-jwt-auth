package com.simplejwtauth.application.port.in;

import com.simplejwtauth.domain.model.AuthToken;

public interface RefreshUseCase {
    AuthToken refresh(String refreshToken);
}
