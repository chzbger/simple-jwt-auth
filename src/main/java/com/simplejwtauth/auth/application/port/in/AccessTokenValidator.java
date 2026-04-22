package com.simplejwtauth.auth.application.port.in;

public interface AccessTokenValidator {
    Long validateAndGetUserId(String token);
}
