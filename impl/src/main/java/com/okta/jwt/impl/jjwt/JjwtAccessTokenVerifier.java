/*
 * Copyright 2018-Present Okta, Inc.
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

import com.okta.jwt.AccessTokenVerifier;
import com.okta.jwt.Jwt;
import com.okta.jwt.JwtVerificationException;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SigningKeyResolver;

import java.time.Clock;
import java.time.Duration;

/**
 * Classes in this `impl` implementation package may change in NON backward compatible way, and should ONLY be used as
 * a "runtime" dependency.
 */
public class JjwtAccessTokenVerifier extends TokenVerifierSupport
                                     implements AccessTokenVerifier {

    private final String audience;

    public JjwtAccessTokenVerifier(String issuer,
                                   String audience,
                                   Duration leeway,
                                   SigningKeyResolver signingKeyResolver) {

        super(issuer, leeway, signingKeyResolver, Clock.systemDefaultZone());
        this.audience = audience;
    }

    public JjwtAccessTokenVerifier(String issuer,
                                   String audience,
                                   Duration leeway,
                                   SigningKeyResolver signingKeyResolver,
                                   Clock clock) {

        super(issuer, leeway, signingKeyResolver, clock);
        this.audience = audience;
    }

    @Override
    public Jwt decode(String accessToken) throws JwtVerificationException {
        return decode(accessToken, parser(), new ClaimsValidator.ContainsAudienceClaimsValidator(audience));
    }

    //To allow explicitly push changes
    @Override
    public void loadJwks() throws JwtException {
       RemoteJwkSigningKeyResolver remoteJwkSigningKeyResolver=  (RemoteJwkSigningKeyResolver) this.getKeyResolver();
       remoteJwkSigningKeyResolver.updateKeys();
    }
}
