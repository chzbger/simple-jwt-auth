package com.simplejwtauth.auth.application.port.in;

import com.simplejwtauth.auth.domain.AuthToken;

public interface LoginUseCase {
    AuthToken login(String username, String password);
}
