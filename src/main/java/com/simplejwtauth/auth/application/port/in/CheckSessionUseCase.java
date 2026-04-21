package com.simplejwtauth.auth.application.port.in;

public interface CheckSessionUseCase {
    String currentUserId(String refreshToken);
}
