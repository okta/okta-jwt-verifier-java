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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.okta.jwt.JoseException;
import com.okta.jwt.Jwt;
import com.okta.jwt.JwtVerifier;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;

/**
 * Nimbus based {@link JwtVerifier}.  JWTs validated with this class will be checked for a valid signature, expiration,
 * issuer, and client/audience.
 */
public class NimbusJwtVerifier implements JwtVerifier {

    static final String TOKEN_TYPE_KEY = "token_type";
    static final String TOKEN_TYPE_ACCESS = "access_token";
    static final String TOKEN_TYPE_ID = "id_token";

    private final ConfigurableJWTProcessor jwtProcessor;

    public NimbusJwtVerifier(ConfigurableJWTProcessor jwtProcessor) {
        Assert.notNull(jwtProcessor,   "Nimbus JWT Processor cannot be empty");
        this.jwtProcessor = jwtProcessor;
    }

    @Override
    public Jwt decodeIdToken(String jwtString) throws JoseException {
        Assert.notNull(jwtString, "JWT String cannot be null");
        return decode(jwtString, TOKEN_TYPE_ID);
    }

    @Override
    public Jwt decodeAccessToken(String jwtString) throws JoseException {
        Assert.notNull(jwtString, "JWT String cannot be null");
        return decode(jwtString, TOKEN_TYPE_ACCESS);
    }

    private Jwt decode(String jwtString, String tokenType) throws JoseException {

        SimpleSecurityContext context = new SimpleSecurityContext();
        context.put(TOKEN_TYPE_KEY, tokenType);

        try {
            JWTClaimsSet claimsSet = jwtProcessor.process(jwtString, context);

            return new DefaultJwt(jwtString,
                    nullSafeToInstant(claimsSet.getIssueTime()),
                    nullSafeToInstant(claimsSet.getExpirationTime()),
                    claimsSet.getClaims());

        } catch (BadJOSEException | JOSEException | ParseException e) {
            throw new JoseException("Failed to validate JWT string", e);
        }
    }

    private Instant nullSafeToInstant(Date date) {
        return date != null
                ? date.toInstant()
                : null;
    }
}
