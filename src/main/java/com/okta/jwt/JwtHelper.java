package com.okta.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.okta.jwt.impl.NimbusJwtVerifier;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class JwtHelper {

    private String issuerUrl;
    private String clientOrAudience;

    public JwtHelper setIssuerUrl(String issuerUrl) {

        // Strip the last /, as Okta does NOT include this in the token
        String tmpUrl = issuerUrl;
        if (tmpUrl != null) {
            tmpUrl = tmpUrl.replaceAll("/$", "");
        }
        this.issuerUrl = tmpUrl;

        return this;
    }

    public JwtHelper setClientOrAudience(String clientOrAudience) {
        this.clientOrAudience = clientOrAudience;
        return this;
    }

    public JwtVerifier build() throws IOException, ParseException {

        assert StringUtils.isEmpty(issuerUrl) : "IssuerUrl cannot be empty";
        assert StringUtils.isEmpty(clientOrAudience) : "ClientId/Audience cannot be empty";

        URL providerConfigurationURL = URI.create(issuerUrl + "/").resolve(".well-known/openid-configuration").toURL();

        String metadata = IOUtils.readInputStreamToString(providerConfigurationURL.openStream(), StandardCharsets.UTF_8);
        OIDCProviderMetadata providerMetadata = OIDCProviderMetadata.parse(metadata);

        // Keys URI from discovery
        URL keysURI = providerMetadata.getJWKSetURI().toURL();

        // Set up a JWT processor to parse the tokens and then check their signature
        // and validity time window (bounded by the "iat", "nbf" and "exp" claims)
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();

        // The public RSA keys to validate the signatures will be sourced from the
        // OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
        // object caches the retrieved keys to speed up subsequent look-ups and can
        // also gracefully handle key-rollover
        JWKSource keySource = new RemoteJWKSet(keysURI);

        // The expected JWS algorithm of the access tokens (agreed out-of-band)
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

        // Configure the JWT processor with a key selector to feed matching public
        // RSA keys sourced from the JWK set URL
        JWSKeySelector keySelector = new JWSVerificationKeySelector(expectedJWSAlg, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);

        return new NimbusJwtVerifier(issuerUrl, clientOrAudience, jwtProcessor);
    }

}
