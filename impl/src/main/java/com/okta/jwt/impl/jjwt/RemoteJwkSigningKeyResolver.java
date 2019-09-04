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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.okta.jwt.impl.http.HttpClient;
import com.okta.jwt.impl.jjwt.models.JwkKey;
import com.okta.jwt.impl.jjwt.models.JwkKeys;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SigningKeyResolver;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

final class RemoteJwkSigningKeyResolver implements SigningKeyResolver {

    private final URL jwkUri;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, Key> keyMap = new HashMap<>();

    RemoteJwkSigningKeyResolver(URL jwkUri, HttpClient httpClient) {
        this.jwkUri = jwkUri;
        this.httpClient = httpClient;
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        return getKey(header.getKeyId());
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, String plaintext) {
        return getKey(header.getKeyId());
    }

    private Key getKey(String keyId) {

        Key result = keyMap.get(keyId);
        if (result != null) {
            return result;
        }

        updateKeys();
        return keyMap.get(keyId);
    }

    private void updateKeys() {
        try {
            Map<String, Key> newKeys =
            objectMapper.readValue(httpClient.get(jwkUri), JwkKeys.class).getKeys().stream()
                .filter(jwkKey -> "sig".equals(jwkKey.getPublicKeyUse()))
                .filter(jwkKey -> "RSA".equals(jwkKey.getKeyType()))
                .collect(Collectors.toMap(JwkKey::getKeyId, jwkKey -> {
                    BigInteger modulus = base64ToBigInteger(jwkKey.getPublicKeyModulus());
                    BigInteger exponent = base64ToBigInteger(jwkKey.getPublicKeyExponent());
                    RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
                    try {
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        return keyFactory.generatePublic(rsaPublicKeySpec);
                    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                        throw new IllegalStateException("Failed to parse public key");
                    }
               }));

            keyMap.clear();
            keyMap.putAll(newKeys);

        } catch (IOException e) {
            throw new JwtException("Failed to fetch keys from URL: " + jwkUri, e);
        }
    }

    private BigInteger base64ToBigInteger(String value) {
        return new BigInteger(1, Base64.getUrlDecoder().decode(value));
    }
}