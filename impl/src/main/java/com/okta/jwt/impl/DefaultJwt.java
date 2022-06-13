/*
 * Copyright 2017 Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.okta.jwt.impl;

import com.okta.jwt.Jwt;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import static com.okta.commons.lang.Assert.notEmpty;
import static com.okta.commons.lang.Assert.notNull;

/**
 * Default simple bean implementation of {@link Jwt}.
 *
 * Classes in this `impl` implementation package may change in NON backward compatible way, and should ONLY be used as
 * a "runtime" dependency.
 */
public class DefaultJwt implements Jwt {

    private final String tokenValue;
    private final Map<String, Object> claims;
    private final Instant issuedAt;
    private final Instant expiresAt;

    /**
     * Creates an instance based on input from an already parsed and validated JWT.
     * @param tokenValue Original JWT string
     * @param issuedAt The value from the {@code iat} claim, as an {@link Instant}
     * @param expiresAt The value from the {@code exp} claim, as an {@link Instant}
     * @param claims A map of the original claim values in the JWT
     */
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
