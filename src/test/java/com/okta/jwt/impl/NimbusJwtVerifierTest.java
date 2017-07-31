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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.okta.jwt.JoseException;
import com.okta.jwt.JwtVerifier;
import org.testng.annotations.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

public class NimbusJwtVerifierTest {

    @Test
    public void testValidToken() throws NoSuchAlgorithmException, JOSEException, JoseException {

        SignedJwtTestStructure testStructure = new SignedJwtTestStructure("testIssuer1", "testClient1", new Date(), new Date(System.currentTimeMillis() + 10000));

        JwtVerifier verifier = new NimbusJwtVerifier("testIssuer1", "testClient1", testStructure.jwtProcessor);
        verifier.decodeAccessToken(testStructure.jwtString);
//        verifier.decodeIdToken(testStructure.jwtString);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testNullToken() throws NoSuchAlgorithmException, JOSEException, JoseException {

        SignedJwtTestStructure testStructure = new SignedJwtTestStructure("testIssuer1", "testClient1", new Date(), new Date(System.currentTimeMillis() + 10000));

        JwtVerifier verifier = new NimbusJwtVerifier("testIssuer1", "testClient1", testStructure.jwtProcessor);
        verifier.decodeAccessToken(null);
    }

    @Test(expectedExceptions = JoseException.class)
    public void testExpiredToken() throws NoSuchAlgorithmException, JOSEException, JoseException {

        SignedJwtTestStructure testStructure = new SignedJwtTestStructure("testIssuer", "testClient", new Date(), new Date(System.currentTimeMillis() - 10000));

        JwtVerifier verifier = new NimbusJwtVerifier("testIssuer", "testClient", testStructure.jwtProcessor);
        verifier.decodeAccessToken(testStructure.jwtString);
    }

    @Test(expectedExceptions = JoseException.class)
    public void testCreatedFuture() throws NoSuchAlgorithmException, JOSEException, JoseException {

        SignedJwtTestStructure testStructure = new SignedJwtTestStructure("testIssuer", "testClient", new Date(System.currentTimeMillis() + 10000), new Date());

        JwtVerifier verifier = new NimbusJwtVerifier("testIssuer", "testClient", testStructure.jwtProcessor);
        verifier.decodeAccessToken(testStructure.jwtString);
    }

    @Test(expectedExceptions = JoseException.class)
    public void testInvalidClient() throws NoSuchAlgorithmException, JOSEException, JoseException {

        SignedJwtTestStructure testStructure = new SignedJwtTestStructure("testIssuer", "testClient", new Date(), new Date(System.currentTimeMillis() - 10000));

        JwtVerifier verifier = new NimbusJwtVerifier("testIssuer", "wrong-client", testStructure.jwtProcessor);
        verifier.decodeAccessToken(testStructure.jwtString);
    }

    @Test(expectedExceptions = JoseException.class)
    public void testInvalidIssuer() throws NoSuchAlgorithmException, JOSEException, JoseException {

        SignedJwtTestStructure testStructure = new SignedJwtTestStructure("testIssuer", "testClient", new Date(), new Date(System.currentTimeMillis() - 10000));

        JwtVerifier verifier = new NimbusJwtVerifier("wrong-issuer", "testClient", testStructure.jwtProcessor);
        verifier.decodeAccessToken(testStructure.jwtString);
    }

    private class SignedJwtTestStructure {

        String issuer;
        String client;
        Date issuedAt;
        Date expireAt;
        DefaultJWTProcessor jwtProcessor;
        String jwtString;

        public SignedJwtTestStructure(String issuer, String client, Date issuedAt, Date expireAt) throws NoSuchAlgorithmException, JOSEException {
            this.issuer = issuer;
            this.client = client;
            this.issuedAt = issuedAt;
            this.expireAt = expireAt;

            String kid = "123";

            // RSA signatures require a public and private RSA key pair,
            // the public key must be made known to the JWS recipient to
            // allow the signatures to be verified
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(1024);

            KeyPair kp = keyGenerator.genKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();

            // Create RSA-signer with the private key
            JWSSigner signer = new RSASSASigner(privateKey);

            // Prepare JWS object with simple string as payload
            SignedJWT jwtObject = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build(),
                    new JWTClaimsSet.Builder()
                            .issuer(this.issuer)
                            .audience(this.client)
                            .claim("cid", this.client)
                            .issueTime(issuedAt)
                            .expirationTime(expireAt)
                            .build());

            // Compute the RSA signature
            jwtObject.sign(signer);

            this.jwtString = jwtObject.serialize();

            JWKSet jwkSet = new JWKSet(new RSAKey(publicKey, KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, kid, null, null, null, null, null));
            ImmutableJWKSet immutableJWKSet = new ImmutableJWKSet(jwkSet);

            this.jwtProcessor = new DefaultJWTProcessor();
            JWSKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.RS256, immutableJWKSet);
            jwtProcessor.setJWSKeySelector(keySelector);

        }
    }
}
