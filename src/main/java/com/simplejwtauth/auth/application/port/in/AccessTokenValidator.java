package com.simplejwtauth.auth.application.port.in;

public interface AccessTokenValidator {
    String validateAndGetUserId(String token);
}
