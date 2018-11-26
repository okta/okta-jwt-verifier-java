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
package com.okta.jwt.impl.jjwt.models;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * Classes in this `impl` implementation package may change in NON backward compatible way, and should ONLY be used as
 * a "runtime" dependency.
 */
public class JwkKey {

    @JsonProperty("kty")
    private String keyType;

    @JsonProperty("alg")
    private String algorithm;

    @JsonProperty("kid")
    private String keyId;

    @JsonProperty("use")
    private String publicKeyUse;

    @JsonProperty("e")
    private String publicKeyExponent;

    @JsonProperty("n")
    private String publicKeyModulus;

    public String getKeyType() {
        return keyType;
    }

    public JwkKey setKeyType(String keyType) {
        this.keyType = keyType;
        return this;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public JwkKey setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public String getKeyId() {
        return keyId;
    }

    public JwkKey setKeyId(String keyId) {
        this.keyId = keyId;
        return this;
    }

    public String getPublicKeyUse() {
        return publicKeyUse;
    }

    public JwkKey setPublicKeyUse(String publicKeyUse) {
        this.publicKeyUse = publicKeyUse;
        return this;
    }

    public String getPublicKeyExponent() {
        return publicKeyExponent;
    }

    public JwkKey setPublicKeyExponent(String publicKeyExponent) {
        this.publicKeyExponent = publicKeyExponent;
        return this;
    }

    public String getPublicKeyModulus() {
        return publicKeyModulus;
    }

    public JwkKey setPublicKeyModulus(String publicKeyModulus) {
        this.publicKeyModulus = publicKeyModulus;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JwkKey jwkKey = (JwkKey) o;
        return Objects.equals(keyType, jwkKey.keyType) &&
                Objects.equals(algorithm, jwkKey.algorithm) &&
                Objects.equals(keyId, jwkKey.keyId) &&
                Objects.equals(publicKeyUse, jwkKey.publicKeyUse) &&
                Objects.equals(publicKeyExponent, jwkKey.publicKeyExponent) &&
                Objects.equals(publicKeyModulus, jwkKey.publicKeyModulus);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyType, algorithm, keyId, publicKeyUse, publicKeyExponent, publicKeyModulus);
    }
}
