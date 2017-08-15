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
package com.okta.jwt.impl

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.okta.jwt.JoseException
import com.okta.jwt.JwtVerifier
import org.testng.annotations.Test

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import static com.okta.jwt.TestSupport.*

class NimbusJwtVerifierTest {

    private int clockSkewOffset = 65 * 1000 // default skew is 60 seconds

    @Test
    void testValidAccessToken() throws NoSuchAlgorithmException, JOSEException, JoseException {

        SignedJwtTestStructure testStructure = new SignedJwtTestStructure("testIssuer1", "testAudience1", "testClient1", null, new Date(), new Date(System.currentTimeMillis() + 10000), "testIssuer1", "testAudience1")

        JwtVerifier verifier = new NimbusJwtVerifier(testStructure.jwtProcessor)

        verifier.decodeAccessToken(testStructure.jwtAccessToken)
    }

    @Test
    void testValidIdTokenNoNonce() throws NoSuchAlgorithmException, JOSEException, JoseException {

        SignedJwtTestStructure testStructure = new SignedJwtTestStructure("testIssuer1", "testAudience1", "testClient1", null, new Date(), new Date(System.currentTimeMillis() + 10000), "testIssuer1", "testClient1")

        JwtVerifier verifier = new NimbusJwtVerifier(testStructure.jwtProcessor)

        verifier.decodeIdToken(testStructure.jwtIdToken, testStructure.nonce)
    }

    @Test
    void testValidIdTokenWithNonce() throws NoSuchAlgorithmException, JOSEException, JoseException {

        SignedJwtTestStructure testStructure = new SignedJwtTestStructure("testIssuer1", "testAudience1", "testClient1", "nonce1", new Date(), new Date(System.currentTimeMillis() + 10000), "testIssuer1", "testClient1", "nonce1")

        JwtVerifier verifier = new NimbusJwtVerifier(testStructure.jwtProcessor)

        verifier.decodeIdToken(testStructure.jwtIdToken, testStructure.nonce)
    }

    @Test
    void testNullToken() throws NoSuchAlgorithmException, JOSEException, JoseException {

        SignedJwtTestStructure testStructure = new SignedJwtTestStructure("testIssuer1", "testAudience1", "testClient1", null, new Date(), new Date(System.currentTimeMillis() + 10000), "testIssuer1", "testAudience1")

        JwtVerifier verifier = new NimbusJwtVerifier(testStructure.jwtProcessor)

        expect(IllegalArgumentException) {
            verifier.decodeAccessToken(null)
        }

        expect(IllegalArgumentException) {
            verifier.decodeIdToken(null, testStructure.nonce)
        }
    }

    @Test
    void testExpiredToken() throws NoSuchAlgorithmException, JOSEException, JoseException {

        SignedJwtTestStructure testStructure = new SignedJwtTestStructure("testIssuer", "testAudience", "testClient", null, new Date(), new Date(System.currentTimeMillis() - clockSkewOffset), "testIssuer", "testAudience")

        JwtVerifier verifier = new NimbusJwtVerifier(testStructure.jwtProcessor)
        expect(JoseException) {
            verifier.decodeAccessToken(testStructure.jwtAccessToken)
        }
        expect(JoseException) {
            verifier.decodeIdToken(testStructure.jwtAccessToken, testStructure.nonce)
        }
    }

    @Test
    void testCreatedFuture() throws NoSuchAlgorithmException, JOSEException, JoseException {

        SignedJwtTestStructure testStructure = new SignedJwtTestStructure("testIssuer", "testAudience", "testClient", null, new Date(System.currentTimeMillis() + clockSkewOffset), new Date(), "testIssuer", "testAudience")

        JwtVerifier verifier = new NimbusJwtVerifier(testStructure.jwtProcessor)

        expect(JoseException) {
            verifier.decodeAccessToken(testStructure.jwtAccessToken)
        }
        expect(JoseException) {
            verifier.decodeIdToken(testStructure.jwtAccessToken, testStructure.nonce)
        }
    }

    @Test
    void testInvalidClient() throws NoSuchAlgorithmException, JOSEException, JoseException {

        SignedJwtTestStructure testStructure = new SignedJwtTestStructure("testIssuer", "testAudience", "testClient", null, new Date(), new Date(System.currentTimeMillis() - 10000), "testIssuer",  "wrong-audience")

        JwtVerifier verifier = new NimbusJwtVerifier(testStructure.jwtProcessor)

        expect(JoseException) {
            verifier.decodeAccessToken(testStructure.jwtAccessToken)
        }
        expect(JoseException) {
            verifier.decodeIdToken(testStructure.jwtAccessToken, testStructure.nonce)
        }
    }

    @Test
    void testInvalidIssuer() throws NoSuchAlgorithmException, JOSEException, JoseException {

        SignedJwtTestStructure testStructure = new SignedJwtTestStructure("testIssuer", "testAudience", "testClient", null, new Date(), new Date(System.currentTimeMillis() - 10000), "wrong-issuer", "testAudience")

        JwtVerifier verifier = new NimbusJwtVerifier(testStructure.jwtProcessor)

        expect(JoseException) {
            verifier.decodeAccessToken(testStructure.jwtAccessToken)
        }
        expect(JoseException) {
            verifier.decodeIdToken(testStructure.jwtAccessToken, testStructure.nonce)
        }
    }

    private class SignedJwtTestStructure {

        String issuer
        String audience
        String client
        String nonce
        Date issuedAt
        Date expireAt
        DefaultJWTProcessor jwtProcessor
        String jwtAccessToken
        String jwtIdToken

        String jwtIssuer
        String jwtAudience
        String jwtNonce

        SignedJwtTestStructure(String issuer, String audience, String client, String nonce, Date issuedAt, Date expireAt, String jwtIssuer=null, String jwtAudience=null, String jwtNonce=null)
                throws NoSuchAlgorithmException, JOSEException {

            this.issuer = issuer
            this.audience = audience
            this.client = client
            this.issuedAt = issuedAt
            this.expireAt = expireAt

            this.jwtIssuer = jwtIssuer
            this.jwtAudience = jwtAudience
            this.nonce = nonce

            if (this.jwtIssuer == null) {
                this.jwtIssuer = issuer
            }

            if (this.jwtAudience == null) {
                this.jwtAudience = audience
            }

            if (this.jwtNonce == null) {
                this.jwtNonce = nonce
            }

            String kid = "123"

            // RSA signatures require a public and private RSA key pair,
            // the public key must be made known to the JWS recipient to
            // allow the signatures to be verified
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA")
            keyGenerator.initialize(1024)

            KeyPair kp = keyGenerator.genKeyPair()
            RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic()
            RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate()

            // Create RSA-signer with the private key
            JWSSigner signer = new RSASSASigner(privateKey)

            this.jwtAccessToken = buildJwt("cid", kid, signer)
            this.jwtIdToken = buildJwt("aud", kid, signer)

            JWKSet jwkSet = new JWKSet(new RSAKey(publicKey, KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, kid, null, null, null, null, null))
            ImmutableJWKSet immutableJWKSet = new ImmutableJWKSet(jwkSet)

            this.jwtProcessor = new DefaultJWTProcessor()
            JWSKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.RS256, immutableJWKSet)
            jwtProcessor.setJWTClaimsSetVerifier(new OktaJWTClaimsVerifier(issuer, audience, client))
            jwtProcessor.setJWSKeySelector(keySelector)
        }

        String buildJwt(String clientClaim, String kid, RSASSASigner signer) {

            SignedJWT jwtObject = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build(),
                    new JWTClaimsSet.Builder()
                            .issuer(this.jwtIssuer)
                            .subject("joe.coder@example.com")
                            .claim(clientClaim, this.jwtAudience)
                            .claim("nonce", this.jwtNonce)
                            .audience(this.jwtAudience)
                            .issueTime(issuedAt)
                            .notBeforeTime(issuedAt)
                            .expirationTime(expireAt)
                            .build())

            // Compute the RSA signature
            jwtObject.sign(signer)

            return jwtObject.serialize()
        }
    }
}