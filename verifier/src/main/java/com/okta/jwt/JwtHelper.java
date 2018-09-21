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
package com.okta.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.okta.jwt.impl.NimbusJwtVerifier;
import com.okta.jwt.impl.OktaJWTClaimsVerifier;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public final class JwtHelper {

    private String issuerUrl;
    private String audience = "api://default";
    private String clientId;
    private int connectionTimeout = 1000;
    private int readTimeout = 1000;

    public JwtHelper setIssuerUrl(String issuerUrl) {

        // Strip the last /, as Okta does NOT include this in the token
        String tmpUrl = issuerUrl;
        if (tmpUrl != null) {
            tmpUrl = tmpUrl.replaceAll("/$", "");
        }
        this.issuerUrl = tmpUrl;

        return this;
    }

    public JwtHelper setAudience(String audience) {
        this.audience = audience;
        return this;
    }

    public JwtHelper setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public JwtHelper setConnectionTimeout(int connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
        return this;
    }

    public JwtHelper setReadTimeout(int readTimeout) {
        this.readTimeout = readTimeout;
        return this;
    }

    public JwtVerifier build() throws IOException {

        notEmpty(issuerUrl, "IssuerUrl cannot be empty");
        notEmpty(audience, "Audience cannot be empty");

        // Keys URI can be hard codeded to avoid an extra call to the discovery endpoint
        URL keysURI = URI.create(issuerUrl).resolve("/v1/keys").toURL();

        // Set up a JWT processor to parse the tokens and then check their signature
        // and validity time window (bounded by the "iat", "nbf" and "exp" claims)
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();

        // The public RSA keys to validate the signatures will be sourced from the
        // OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
        // object caches the retrieved keys to speed up subsequent look-ups and can
        // also gracefully handle key-rollover
        JWKSource keySource = new RemoteJWKSet(keysURI, new DefaultResourceRetriever(
                connectionTimeout,
                readTimeout,
                RemoteJWKSet.DEFAULT_HTTP_SIZE_LIMIT));

        // The expected JWS algorithm of the access tokens (agreed out-of-band)
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

        // Configure the JWT processor with a key selector to feed matching public
        // RSA keys sourced from the JWK set URL
        JWSKeySelector keySelector = new JWSVerificationKeySelector(expectedJWSAlg, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);
        jwtProcessor.setJWTClaimsSetVerifier(new OktaJWTClaimsVerifier(issuerUrl, audience, clientId));

        return new NimbusJwtVerifier(jwtProcessor);
    }

    /**
     * Exposed for help testing only. The actual implementation just uses Nimbus's IOUtils.
     * @param url .well-known metadata url
     * @return String content of the URL
     * @throws IOException if there is a problem opening the URL stream.
     */
    String readMetadataFromUrl(URL url) throws IOException {
        return IOUtils.readInputStreamToString(url.openStream(), StandardCharsets.UTF_8);
    }

    private void notEmpty(String value, String message) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(message);
        }
    }
}