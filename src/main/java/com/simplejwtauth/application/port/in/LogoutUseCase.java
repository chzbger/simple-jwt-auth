package com.simplejwtauth.application.port.in;

public interface LogoutUseCase {
    void logout(String refreshToken);
}
