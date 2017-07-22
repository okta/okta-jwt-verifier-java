package com.okta.jwt;

public class JoseException extends Exception {

    public JoseException(String message) {
        super(message);
    }

    public JoseException(String message, Throwable cause) {
        super(message, cause);
    }
}
