package com.simplejwtauth.auth.application.error;

import lombok.Getter;

public class InvalidTokenException extends RuntimeException {

    public enum Type { EXPIRED, INVALID }

    @Getter
    private final Type type;

    public InvalidTokenException(Type type) {
        super(type.name());
        this.type = type;
    }
}
