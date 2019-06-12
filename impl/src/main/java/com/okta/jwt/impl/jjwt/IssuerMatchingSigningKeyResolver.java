/*
 * Copyright 2019-Present Okta, Inc.
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
package com.okta.jwt.impl.jjwt;

import io.jsonwebtoken.ClaimJwtException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.IncorrectClaimException;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolver;

import java.security.Key;

/**
 * A {@link SigningKeyResolver} that validates the issuer claim before resolving a key.  This allows for a more
 * targeted exception message to allow the developer to track down the cause.
 * @since 0.5.0
 */
final class IssuerMatchingSigningKeyResolver implements SigningKeyResolver {

    private final String issuer;
    private final SigningKeyResolver delegate;

    IssuerMatchingSigningKeyResolver(String issuer, SigningKeyResolver delegate) {
        this.issuer = issuer;
        this.delegate = delegate;
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {

        // avoid fetching keys if the issuer is not correct
        if (!issuer.equals(claims.getIssuer())) {
            String msg = String.format(ClaimJwtException.INCORRECT_EXPECTED_CLAIM_MESSAGE_TEMPLATE, Claims.ISSUER, issuer, claims.getIssuer());
            IncorrectClaimException e = new IncorrectClaimException(header, claims, msg);
            e.setClaimName(Claims.ISSUER);
            throw e;
        }

        return delegate.resolveSigningKey(header, claims);
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, String plaintext) {
        return delegate.resolveSigningKey(header, plaintext);
    }
}
