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

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;

import java.util.List;
import java.util.Map;

import static com.okta.jwt.impl.NimbusJwtVerifier.NONCE_KEY;
import static com.okta.jwt.impl.NimbusJwtVerifier.TOKEN_TYPE_KEY;
import static com.okta.jwt.impl.NimbusJwtVerifier.TOKEN_TYPE_ACCESS;
import static com.okta.jwt.impl.NimbusJwtVerifier.TOKEN_TYPE_ID;

public class OktaJWTClaimsVerifier<C extends SecurityContext> extends DefaultJWTClaimsVerifier<C> {

    private static final String CID_CLAIM = "cid";

    private final String issuer;
    private final String audience;
    private final String clientId;

    public OktaJWTClaimsVerifier(String issuer, String audience, String clientId) {
        this.issuer = issuer;
        this.audience = audience;
        this.clientId = clientId;
    }

    @Override
    public void verify(JWTClaimsSet jwt, C context) throws BadJWTException {

        Assert.notNull(jwt, "JWTClaimsSet cannot be null");

        // validate expire / not before time
        super.verify(jwt, context);

        // access_token by default
        String tokenType = TOKEN_TYPE_ACCESS;
        String nonce = null;

        if (context instanceof Map) {
            Map contextMap = ((Map) context);

            Object value = contextMap.get(TOKEN_TYPE_KEY);
            if (value != null) {
                tokenType = value.toString();
            }

            nonce = (String) contextMap.get(NONCE_KEY);
        }

        // validate issuer
        Object claimIssuer = jwt.getClaims().get("iss");
        if (!issuer.equals(claimIssuer)) {
            throw new BadJWTException(String.format("Failed to validate jwt string, invalid issuer, " +
                    "expected '%s', found '%s'", issuer, claimIssuer));
        }

        // Access Token Validation
        if (TOKEN_TYPE_ACCESS.equals(tokenType)) {
            List<String> resolvedAudience = jwt.getAudience();
            // the expected audience MUST be in this list
            if (CollectionUtils.isEmpty(resolvedAudience) || !resolvedAudience.contains(audience)) {
                throw new BadJWTException(String.format("Failed to validate jwt string, invalid audience " +
                        "claim 'aud', expected '%s', but found '%s'", audience, resolvedAudience));
            }

            // if an the client id is set, it must be verified
            if (StringUtils.isNotEmpty(clientId)) {
                Object resolvedClientId = jwt.getClaim(CID_CLAIM);
                if (!clientId.equals(resolvedClientId)) {
                    throw new BadJWTException(String.format("Failed to validate jwt string, invalid clientId found in " +
                        "claim 'cid', expected '%s', but found '%s'", clientId, resolvedClientId));
                }
            }
        }

        // ID Token Validation
        else if (TOKEN_TYPE_ID.equals(tokenType)) {

            Assert.notNull(clientId, "An OAuth clientId must be specified when validating ID Tokens.");

            List<String> resolvedAudience = jwt.getAudience();
            // the expected audience MUST be in this list
            if (CollectionUtils.isEmpty(resolvedAudience) || !resolvedAudience.contains(clientId)) {
                throw new BadJWTException(String.format("Failed to validate jwt string, invalid clientId found in " +
                        "claim 'aud', expected '%s', but found '%s'", clientId, resolvedAudience));
            }

            // validate nonce
            Object resolvedNonce = jwt.getClaim("nonce");
            if ( nonce != null && !nonce.equals(resolvedNonce)) {
                throw new BadJWTException(String.format("Invalid nonce found in ID Token, expected '%s', but found '%s'", nonce, resolvedNonce));
            }

            String subject = jwt.getSubject();
            if (subject == null) {
                throw new BadJWTException("Invalid ID Token, missing subject claim ('sub')");
            }

        }

        // Unknown Token Type
        else {
            throw new BadJWTException(String.format("Unknown token type: '%s'", tokenType));
        }
    }
}