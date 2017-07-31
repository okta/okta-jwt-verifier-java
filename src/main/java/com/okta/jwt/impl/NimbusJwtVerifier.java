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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.okta.jwt.JoseException;
import com.okta.jwt.Jwt;
import com.okta.jwt.JwtVerifier;

import java.text.ParseException;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;

/**
 * Nimbus based {@link JwtVerifier}.  JWTs validated with this class will be checked for a valid signature, expiration,
 * issuer, and client/audience.
 */
public class NimbusJwtVerifier implements JwtVerifier {

    private final String issuer;
    private final String clientOrAudience;
    private final ConfigurableJWTProcessor jwtProcessor;

    public NimbusJwtVerifier(String issuer,
                             String clientOrAudience,
                             ConfigurableJWTProcessor jwtProcessor) {

        Assert.notNull(issuer,   "Issuer cannot be empty");
        Assert.notNull(clientOrAudience, "Client ID/Audience cannot be empty");
        Assert.notNull(jwtProcessor,   "Nimbus JWT Processor cannot be empty");

        this.issuer = issuer;
        this.clientOrAudience = clientOrAudience;
        this.jwtProcessor = jwtProcessor;
    }

    @Override
    public Jwt decodeIdToken(String jwtString) throws JoseException {

        return verifyToken(decode(jwtString),"aud");
    }

    @Override
    public Jwt decodeAccessToken(String jwtString) throws JoseException {
        Assert.notNull(jwtString, "JWT String cannot be null");
        return verifyToken(decode(jwtString),"cid");
    }

    private Jwt decode(String jwtString) throws JoseException {

        try {
            JWTClaimsSet claimsSet = jwtProcessor.process(jwtString, null);

            return new DefaultJwt(jwtString,
                    nullSafeToInstant(claimsSet.getIssueTime()),
                    nullSafeToInstant(claimsSet.getExpirationTime()),
                    claimsSet.getClaims());

        } catch (ParseException e) {
            throw new JoseException("Failed to parse JWT string", e);
        } catch (BadJOSEException | JOSEException e) {
            throw new JoseException("Failed to validate JWT string", e);
        }
    }

    private Instant nullSafeToInstant(Date date) {
        if (date == null) {
            return null;
        }
        return date.toInstant();
    }

    private Jwt verifyToken(Jwt jwt, String clientIdClaim) throws JoseException {

        Instant now = Instant.now();
        if (jwt.getExpiresAt().isBefore(now)) {
            throw new JoseException("JWT is expired");
        }

        if (jwt.getIssuedAt().isAfter(now)) {
            throw new JoseException("JWT was created with a future date");
        }

        Object claimIssuer = jwt.getClaims().get("iss");
        if (!issuer.equals(claimIssuer)) {
            throw new JoseException(String.format("Failed to validate jwt string, invalid issuer, expected '%s', found '%s'", issuer, claimIssuer));
        }

        Object clientId = jwt.getClaims().get(clientIdClaim);
        if (clientId instanceof Collection) {
            Collection clientIdCollection = (Collection) clientId;
            if (!clientIdCollection.contains(clientOrAudience)) {
                throw new JoseException(String.format("Failed to validate jwt string, invalid clientId/audience claim '%s', expected '%s', found '%s'", clientIdClaim, clientOrAudience, clientId));
            }
        }

        if (!clientOrAudience.equals(clientId)) {
            throw new JoseException(String.format("Failed to validate jwt string, invalid clientId/audience claim '%s', expected '%s', found '%s'", clientIdClaim, clientOrAudience, clientId));
        }
        return jwt;
    }
}
