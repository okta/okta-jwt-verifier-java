package com.okta.jwt;

public interface JwtVerifier {

    Jwt decodeIdToken(String jwtString) throws JoseException;

    Jwt decodeAccessToken(String jwtString) throws JoseException;
}