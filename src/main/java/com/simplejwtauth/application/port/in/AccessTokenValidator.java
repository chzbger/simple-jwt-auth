package com.simplejwtauth.application.port.in;

public interface AccessTokenValidator {
    Long validateAndGetUserId(String token);
}
