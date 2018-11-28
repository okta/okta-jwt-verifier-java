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
package com.okta.jwt.it

import groovy.json.JsonOutput
import okhttp3.internal.Util
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer

import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyPair
import java.security.KeyStore
import java.security.PublicKey
import java.security.SecureRandom

import static java.lang.Thread.currentThread

class TokenVerifierITSupport {

    public final static String TEST_PUB_KEY_ID_1 = "TEST_PUB_KEY_ID_1"
    public final static KeyPair TEST_KEY_PAIR_1 = ItUtil.generateRsaKeyPair(2048)
    public final static String TEST_PUB_KEY_ID_2 = "TEST_PUB_KEY_ID_2"
    public final static KeyPair TEST_KEY_PAIR_2 = ItUtil.generateRsaKeyPair(2048)

    void stubKeyResponse(MockWebServer mockWebServer, String keyId, PublicKey publicKey) {
        def pubKeyE = Base64.getUrlEncoder().encodeToString(ItUtil.toIntegerBytes(publicKey.getPublicExponent()))
        def pubKeyN = Base64.getUrlEncoder().encodeToString(ItUtil.toIntegerBytes(publicKey.getModulus()))

        def jsonKeysBody = [
                keys: Collections.singleton([
                       kty: "RSA",
                       alg: "RS256",
                       use: "sig",
                       kid: keyId,
                       e: pubKeyE,
                       n: pubKeyN
                    ])
                ]

        mockWebServer.enqueue(new MockResponse().setBody(JsonOutput.toJson(jsonKeysBody)))
    }

    MockWebServer createMockServer() {

        def outKeyStoreFile = File.createTempFile("testing-keystore", "jks").toPath()
        def keyStoreResource = currentThread().contextClassLoader.getResource("tck-keystore.jks")
        Files.copy(keyStoreResource.openStream(), outKeyStoreFile, StandardCopyOption.REPLACE_EXISTING)
        def keyStorePath = outKeyStoreFile.toFile().absolutePath
        System.setProperty("javax.net.ssl.trustStore", keyStorePath)

        def mockServer = new MockWebServer()
        mockServer.useHttps(sslContext(outKeyStoreFile.toFile().getAbsolutePath(), "password").getSocketFactory(), false)
        return mockServer
    }

    SSLContext sslContext(String keystoreFile, String password) {

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType())
        InputStream inputStream = new FileInputStream(keystoreFile)
        try {
            keystore.load(inputStream, password.toCharArray())
        } finally {
            Util.closeQuietly(inputStream)
        }
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        keyManagerFactory.init(keystore, password.toCharArray())
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(keystore)
        SSLContext sslContext = SSLContext.getInstance("TLS")
        sslContext.init(
            keyManagerFactory.getKeyManagers(),
            trustManagerFactory.getTrustManagers(),
            new SecureRandom())
        return sslContext
    }

}
