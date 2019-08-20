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
import java.net.Proxy;
import java.net.URL;
import java.time.Duration;

abstract class BaseVerifierBuilderSupport<B extends VerifierBuilderSupport, R> implements VerifierBuilderSupport<B, R> {

    private String issuer;
    private Duration leeway = Duration.ofMinutes(2);
    private Duration connectionTimeout = Duration.ofSeconds(1);
    private Duration readTimeout = Duration.ofSeconds(1);
    private Proxy proxy;

    String getIssuer() {
        return issuer;
    }

    public B setIssuer(String issuer) {

        // delay validation until 'validate' method is called
        if (issuer != null) {
            // trim and remove any trailing slash
            this.issuer = issuer.trim().replaceAll("/$", "");
        }
        return self();
    }

    Duration getLeeway() {
        return leeway;
    }

    public B setLeeway(Duration leeway) {
        if (leeway == null || leeway.toMillis() < 0) {
            throw new IllegalArgumentException("leeway must not be null or less than zero");
        }
        this.leeway = leeway;
        return self();
    }

    Duration getConnectionTimeout() {
        return connectionTimeout;
    }

    public B setConnectionTimeout(Duration connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
        return self();
    }

    Duration getReadTimeout() {
        return readTimeout;
    }

    public B setReadTimeout(Duration readTimeout) {
        this.readTimeout = readTimeout;
        return self();
    }

    public Proxy getProxy() {
        return proxy;
    }

    public B setProxy(Proxy proxy) {
        this.proxy = proxy;
        return self();
    }

    @SuppressWarnings("unchecked")
    protected B self() {
        return (B) this;
    }

    protected void validate() {
        ConfigurationValidator.assertIssuer(issuer);
    }

    protected String resolveKeysEndpoint(String issuer) {
        return  issuer.matches(".*/oauth2/.*")
                ? issuer + "/v1/keys"
                : issuer + "/oauth2/v1/keys";
    }

    protected SigningKeyResolver signingKeyResolver() {
        try {
            return new RemoteJwkSigningKeyResolver(
                    new URL(resolveKeysEndpoint(getIssuer())),
                    new OkHttpClient(getConnectionTimeout(), getReadTimeout(), proxy));
        } catch (MalformedURLException e) {
            throw new IllegalStateException("Invalid issuer URL in configuration");
        }
    }
}