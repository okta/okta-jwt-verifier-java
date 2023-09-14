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
import com.okta.commons.http.authc.DisabledAuthenticator;
import com.okta.commons.http.config.HttpClientConfiguration;
import com.okta.jwt.VerifierBuilderSupport;
import com.okta.jwt.impl.http.HttpClient;
import com.okta.jwt.impl.http.OktaCommonsHttpClient;
import io.jsonwebtoken.SigningKeyResolver;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

abstract class BaseVerifierBuilderSupport<B extends VerifierBuilderSupport, R> implements VerifierBuilderSupport<B, R> {

    private String issuer;
    private Duration leeway = Duration.ofMinutes(2);
    private Duration connectionTimeout = Duration.ofSeconds(1);
    private String proxyHost = null;
    private int proxyPort;
    private String proxyUsername = null;
    private String proxyPassword = null;
    private int retryMaxAttempts = 2; /* based on SDK spec */
    private Duration retryMaxElapsed = Duration.ofSeconds(10);
    private Clock clock = Clock.systemDefaultZone();
    private Boolean preloadSigningKeys = false;

    public B getPreloadSigningKeys() {
        return self();
    }

    public B setPreloadSigningKeys(Boolean preloadSigningKeys) {
        this.preloadSigningKeys = preloadSigningKeys;
        return self();
    }



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

    public String getProxyHost() {
        return proxyHost;
    }

    @Override
    public B setProxyHost(String proxyHost) {
        this.proxyHost = proxyHost;
        return self();
    }

    public int getProxyPort() {
        return proxyPort;
    }

    @Override
    public B setProxyPort(int proxyPort) {
        this.proxyPort = proxyPort;
        return self();
    }

    public String getProxyUsername() {
        return proxyUsername;
    }

    @Override
    public B setProxyUsername(String proxyUsername) {
        this.proxyUsername = proxyUsername;
        return self();
    }

    public String getProxyPassword() {
        return proxyPassword;
    }

    @Override
    public B setProxyPassword(String proxyPassword) {
        this.proxyPassword = proxyPassword;
        return self();
    }

    public int getRetryMaxAttempts() {
        return retryMaxAttempts;
    }

    public B setRetryMaxAttempts(int retryMaxAttempts) {
        this.retryMaxAttempts = retryMaxAttempts;
        return self();
    }

    public Duration getMaxHttpRetryElapsed() {
        return retryMaxElapsed;
    }

    public B setRetryMaxElapsed(Duration retryMaxElapsed) {
        this.retryMaxElapsed = retryMaxElapsed;
        return self();
    }

    public Clock getClock() {
        return clock;
    }

    public B setClock(Clock clock) {
        this.clock = clock;
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
           RemoteJwkSigningKeyResolver remoteJwkSigningKeyResolver =  new RemoteJwkSigningKeyResolver(
                            new URL(resolveKeysEndpoint(getIssuer())),
                            httpClient());
           //preload keys during start up. so that if the call the issuer keys fails, its not a runtime exception.
            if (preloadSigningKeys) {
                remoteJwkSigningKeyResolver.updateKeys();
            }
            return remoteJwkSigningKeyResolver;
        } catch (MalformedURLException e) {
            throw new IllegalStateException("Invalid issuer URL in configuration");
        }
    }

    protected HttpClient httpClient() {
        HttpClientConfiguration httpClientConfiguration = new HttpClientConfiguration();
        httpClientConfiguration.setRequestAuthenticator(new DisabledAuthenticator());
        httpClientConfiguration.setConnectionTimeout((int) getConnectionTimeout().getSeconds());
        httpClientConfiguration.setRetryMaxAttempts(getRetryMaxAttempts()); // number of retry attempts
        httpClientConfiguration.setRetryMaxElapsed((int) getMaxHttpRetryElapsed().getSeconds()); // number of seconds
        httpClientConfiguration.setProxyHost(getProxyHost());
        httpClientConfiguration.setProxyPort(getProxyPort());
        httpClientConfiguration.setProxyUsername(getProxyUsername());
        httpClientConfiguration.setProxyPassword(getProxyPassword());
        return new OktaCommonsHttpClient(httpClientConfiguration);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BaseVerifierBuilderSupport<?, ?> that = (BaseVerifierBuilderSupport<?, ?>) o;
        return proxyPort == that.proxyPort &&
                retryMaxAttempts == that.retryMaxAttempts &&
                Objects.equals(issuer, that.issuer) &&
                Objects.equals(leeway, that.leeway) &&
                Objects.equals(connectionTimeout, that.connectionTimeout) &&
                Objects.equals(proxyHost, that.proxyHost) &&
                Objects.equals(proxyUsername, that.proxyUsername) &&
                Objects.equals(proxyPassword, that.proxyPassword) &&
                Objects.equals(retryMaxElapsed, that.retryMaxElapsed) &&
                Objects.equals(clock, that.clock);
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuer, leeway, connectionTimeout, proxyHost, proxyPort, proxyUsername, proxyPassword, retryMaxAttempts, retryMaxElapsed, clock);
    }
}