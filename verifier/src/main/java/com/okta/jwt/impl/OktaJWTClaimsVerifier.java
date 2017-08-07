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

import java.util.Collection;
import java.util.Map;

import static com.okta.jwt.impl.NimbusJwtVerifier.*;

public class OktaJWTClaimsVerifier<C extends SecurityContext> extends DefaultJWTClaimsVerifier<C> {

    private final String issuer;
    private final String clientOrAudience;

    public OktaJWTClaimsVerifier(String issuer, String clientOrAudience) {
        this.issuer = issuer;
        this.clientOrAudience = clientOrAudience;
    }

    @Override
    public void verify(JWTClaimsSet jwt, C context) throws BadJWTException {

        Assert.notNull(jwt, "JWTClaimsSet cannot be null");

        // validate expire / not before time
        super.verify(jwt, context);

        // access_token by default
        String tokenType = TOKEN_TYPE_ACCESS;

        if (context instanceof Map) {
            Object value = ((Map) context).get(TOKEN_TYPE_KEY);
            if (value != null) {
                tokenType = value.toString();
            }
        }

        // validate issuer
        Object claimIssuer = jwt.getClaims().get("iss");
        if (!issuer.equals(claimIssuer)) {
            throw new BadJWTException(String.format("Failed to validate jwt string, invalid issuer, " +
                    "expected '%s', found '%s'", issuer, claimIssuer));
        }

        // validate audience
        Object clientId;
        String clientIdClaim;

        if (TOKEN_TYPE_ID.equals(tokenType)) {
            clientIdClaim = "aud";
            clientId = jwt.getAudience();
        }
        else {
            clientIdClaim = "cid";
            clientId = jwt.getClaims().get(clientIdClaim);
        }

        if (clientId instanceof Collection) {
            Collection clientIdCollection = (Collection) clientId;
            if (!clientIdCollection.contains(clientOrAudience)) {
                throw new BadJWTException(String.format("Failed to validate jwt string, invalid clientId/audience " +
                        "claim '%s', expected '%s', found '%s'", clientIdClaim, clientOrAudience, clientId));
            }
        }
        else if (!clientOrAudience.equals(clientId)) {
            throw new BadJWTException(String.format("Failed to validate jwt string, invalid clientId/audience " +
                    "claim '%s', expected '%s', found '%s'", clientIdClaim, clientOrAudience, clientId));
        }
    }
}
