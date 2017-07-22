package com.okta.jwt.impl;

import com.okta.jwt.Jwt;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import static com.okta.jwt.impl.Assert.*;

/**
 * Default simple bean implementation of {@link Jwt}.
 */
public class DefaultJwt implements Jwt {

    private final String tokenValue;
    private final Map<String, Object> claims;
    private Instant issuedAt;
    private Instant expiresAt;

    public DefaultJwt(String tokenValue,
                      Instant issuedAt,
                      Instant expiresAt,
                      Map<String, Object> claims) {

        notNull(tokenValue, "JWT token cannot be null");
        notNull(issuedAt, "issuedAt cannot be null");
        notNull(expiresAt, "expiresAt cannot be null");
        notEmpty(claims, "claims cannot be empty");

        this.tokenValue = tokenValue;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
    }

    @Override
    public String getTokenValue() {
        return tokenValue;
    }

    @Override
    public Instant getIssuedAt() {
        return issuedAt;
    }

    @Override
    public Instant getExpiresAt() {
        return expiresAt;
    }

    @Override
    public Map<String, Object> getClaims() {
        return this.claims;
    }
}
