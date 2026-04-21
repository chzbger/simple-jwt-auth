package com.simplejwtauth.application.port.in;

import com.simplejwtauth.domain.model.AuthToken;

public interface LoginUseCase {
    AuthToken login(String username, String password);
}
