package com.simplejwtauth.application.exception;

public class InvalidTokenException extends RuntimeException {

    public enum Reason { EXPIRED, MALFORMED, SIGNATURE, INVALID }

    private final Reason reason;

    public InvalidTokenException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public InvalidTokenException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
