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

import com.okta.commons.configcheck.ConfigurationValidator;
import com.okta.jwt.VerifierBuilderSupport;
import com.okta.jwt.impl.http.OkHttpClient;
import io.jsonwebtoken.SigningKeyResolver;

import java.net.MalformedURLException;
import java.net.URL;

abstract class BaseVerifierBuilderSupport<B extends VerifierBuilderSupport, R> implements VerifierBuilderSupport<B, R> {

    private String issuer;
    private long leeway = 120L;
    private long connectionTimeout = 1000L;
    private long readTimeout = 1000L;

    public String getIssuer() {
        return issuer;
    }

    public B setIssuer(String issuer) {
        this.issuer = issuer;
        return self();
    }

    public long getLeeway() {
        return leeway;
    }

    public B setLeeway(long leeway) { // TODO use duration
        if (leeway < 0) {
            throw new IllegalArgumentException("leeway must not be less than zero");
        }
        this.leeway = leeway;
        return self();
    }

    public long getConnectionTimeout() {
        return connectionTimeout;
    }

    public B setConnectionTimeout(long connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
        return self();
    }

    public long getReadTimeout() {
        return readTimeout;
    }

    public B setReadTimeout(long readTimeout) {
        this.readTimeout = readTimeout;
        return self();
    }

    @SuppressWarnings("unchecked")
    protected B self() {
        return (B) this;
    }

    protected void validate() {
        ConfigurationValidator.assertIssuer(issuer);
    }

    protected SigningKeyResolver signingKeyResolver() {
        try {
            return  new RemoteJwkSigningKeyResolver(
                            new URL(getIssuer() + "/v1/keys"), // TODO see spec for how to figure out keys endpoint
                            new OkHttpClient(getConnectionTimeout(), getReadTimeout()));
        } catch (MalformedURLException e) {
            throw new IllegalStateException("Invalid issuer URL in configuration");
        }
    }
}
