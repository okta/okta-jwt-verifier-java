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
import io.jsonwebtoken.io.Decoders;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

final class RemoteJwkSigningKeyResolver implements SigningKeyResolver {

    private final URL jwkUri;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Object lock = new Object();
    private volatile Map<String, Key> keyMap = new HashMap<>();

    RemoteJwkSigningKeyResolver(URL jwkUri, HttpClient httpClient) {
        this.jwkUri = jwkUri;
        this.httpClient = httpClient;
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        return getKey(header.getKeyId());
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, byte[] bytes) {
        return getKey(header.getKeyId());
    }

    private Key getKey(String keyId) {

        // check non synchronized to avoid a lock
        Key result = keyMap.get(keyId);
        if (result != null) {
            return result;
        }

        synchronized (lock) {
            // once synchronized, check the map once again the a previously
            // synchronized thread could have already updated they keys
            result = keyMap.get(keyId);
            if (result != null) {
                return result;
            }

            // finally, fallback to updating the keys, an return a value (or null)
            updateKeys();
            return keyMap.get(keyId);
        }
    }

    void updateKeys() {
        try {
            Map<String, Key> newKeys = new HashMap<>();
            for (JwkKey jwkKey : objectMapper.readValue(httpClient.get(jwkUri), JwkKeys.class).getKeys()) {
                if (!"sig".equals(jwkKey.getPublicKeyUse())) {
                    continue;
                }

                Key key = null;
                String keyType = jwkKey.getKeyType();

                if ("RSA".equals(keyType)) {
                    key = parseRsaKey(jwkKey);
                } else if ("oct".equals(keyType)) {
                    key = parseSymmetricKey(jwkKey);
                }

                if (key != null && jwkKey.getKeyId() != null) {
                    newKeys.put(jwkKey.getKeyId(), key);
                }
            }

            keyMap = Collections.unmodifiableMap(newKeys);

        } catch (IOException e) {
            throw new JwtException("Failed to fetch keys from URL: " + jwkUri, e);
        }
    }

    private Key parseRsaKey(JwkKey jwkKey) {
        BigInteger modulus = base64ToBigInteger(jwkKey.getPublicKeyModulus());
        BigInteger exponent = base64ToBigInteger(jwkKey.getPublicKeyExponent());
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(rsaPublicKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Failed to parse RSA public key", e);
        }
    }

    private Key parseSymmetricKey(JwkKey jwkKey) {
        String k = jwkKey.getSymmetricKey();
        if (k == null) {
            throw new IllegalStateException("Symmetric key 'k' value is missing");
        }
        byte[] keyBytes = Decoders.BASE64URL.decode(k);
        // Determine algorithm based on key length or algorithm hint
        String algorithm = determineHmacAlgorithm(jwkKey.getAlgorithm(), keyBytes.length);
        return new SecretKeySpec(keyBytes, algorithm);
    }

    private String determineHmacAlgorithm(String alg, int keyLength) {
        // If algorithm is specified in the JWK, use it to determine the HMAC algorithm
        if (alg != null) {
            switch (alg) {
                case "HS256":
                    return "HmacSHA256";
                case "HS384":
                    return "HmacSHA384";
                case "HS512":
                    return "HmacSHA512";
            }
        }
        // Fallback: determine based on key length
        if (keyLength >= 64) {
            return "HmacSHA512";
        } else if (keyLength >= 48) {
            return "HmacSHA384";
        } else {
            return "HmacSHA256";
        }
    }

    private BigInteger base64ToBigInteger(String value) {
        return new BigInteger(1, Decoders.BASE64URL.decode(value));
    }
}
