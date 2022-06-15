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

import com.okta.jwt.Jwt;
import com.okta.jwt.JwtVerificationException;
import com.okta.jwt.impl.DefaultJwt;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtHandlerAdapter;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.UnsupportedJwtException;

import java.time.Clock;
import java.time.Duration;
import java.util.Date;

abstract class TokenVerifierSupport {

    private final SigningKeyResolver keyResolver;
    private final String issuer;
    private final Duration leeway;
    private final JwtParser jwtParser;
    private final Clock clock;

    TokenVerifierSupport(String issuer,
                         Duration leeway,
                         SigningKeyResolver signingKeyResolver) {
        this.issuer = issuer;
        this.leeway = leeway;
        this.keyResolver = new IssuerMatchingSigningKeyResolver(issuer, signingKeyResolver);
        this.clock = Clock.systemDefaultZone();
        this.jwtParser = buildJwtParser();
    }

    TokenVerifierSupport(String issuer,
                         Duration leeway,
                         SigningKeyResolver signingKeyResolver,
                         Clock clock) {
        this.issuer = issuer;
        this.leeway = leeway;
        this.keyResolver = new IssuerMatchingSigningKeyResolver(issuer, signingKeyResolver);
        this.clock = clock;
        this.jwtParser = buildJwtParser();
    }

    protected JwtParser buildJwtParser() {
        io.jsonwebtoken.Clock jwtClock = () -> Date.from(clock.instant());
        return Jwts.parserBuilder()
                .setSigningKeyResolver(keyResolver)
                .requireIssuer(issuer)
                .setAllowedClockSkewSeconds(leeway.getSeconds())
                .setClock(jwtClock)
                .build();
    }

    protected Jwt decode(String token, JwtParser parser, ClaimsValidator claimsValidator) throws JwtVerificationException {

        if (!parser.isSigned(token)) {
            throw new JwtVerificationException("Token did not contain signature");
        }

        try {
            Jws<Claims> jwt = parser.parse(token, new OktaJwtHandler(claimsValidator));
            return new DefaultJwt(token,
                    jwt.getBody().getIssuedAt().toInstant(),
                    jwt.getBody().getExpiration().toInstant(),
                    jwt.getBody());
        } catch (JwtException e) {
            throw new JwtVerificationException("Failed to parse token", e);
        }
    }

    SigningKeyResolver getKeyResolver() {
        return keyResolver;
    }

    String getIssuer() {
        return issuer;
    }

    Duration getLeeway() {
        return leeway;
    }

    JwtParser parser() {
        return jwtParser;
    }

    static class OktaJwtHandler extends JwtHandlerAdapter<Jws<Claims>> {

        private final ClaimsValidator claimsValidator;

        protected OktaJwtHandler(ClaimsValidator claimsValidator) {
            this.claimsValidator = claimsValidator;
        }

        @Override
       public Jws<Claims> onClaimsJws(Jws<Claims> jws) {

           // validate alg
           String alg = jws.getHeader().getAlgorithm();
           if(!SignatureAlgorithm.RS256.getValue().equals(alg)) {
               throw new UnsupportedJwtException("JWT Header 'alg' of [" + alg + "] is not supported, only RSA25 signatures are supported");
           }

           claimsValidator.validateClaims(jws);
           return jws;
        }
    }
}
