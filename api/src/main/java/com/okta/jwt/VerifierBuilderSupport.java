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
package com.okta.jwt;

import nl.altindag.ssl.SSLFactory;

import java.time.Clock;
import java.time.Duration;

/**
 * JWT Verifier Builder support class (defines common properties used for general JWT validation).
 *
 * @param <B> Builder used for method chaining
 * @param <R> JWT Verifier
 * @since 0.4
 */
public interface VerifierBuilderSupport<B extends VerifierBuilderSupport, R> {

    /**
     * Sets the {@code issuer} the verifier will expect.
     *
     * @param issuer Issuer URL
     * @return a reference to the current builder for use in method chaining
     */
    B setIssuer(String issuer);

    /**
     * Sets the {@code leeway} the verifier will allow.
     *
     * @param leeway clock skew leeway
     * @return a reference to the current builder for use in method chaining
     */
    B setLeeway(Duration leeway);

    /**
     * Sets the {@code connectionTimeout} for the verifier.
     *
     * @param connectionTimeout connection timeout
     * @return a reference to the current builder for use in method chaining
     */
    B setConnectionTimeout(Duration connectionTimeout);

    /**
     * Sets the proxy host used for the configured HTTP proxy.
     *
     * @param proxyHost the proxy host used for the configured HTTP proxy
     * @return a reference to the current builder for use in method chaining
     */
    B setProxyHost(String proxyHost);

    /**
     * Sets the proxy port used for the configured HTTP proxy.
     *
     * @param proxyPort the proxy port used for the configured HTTP proxy
     * @return a reference to the current builder for use in method chaining
     */
    B setProxyPort(int proxyPort);

    /**
     * Sets the proxy username used for the configured HTTP proxy.
     *
     * @param proxyUsername the proxy username used for the configured HTTP proxy
     * @return a reference to the current builder for use in method chaining
     */
    B setProxyUsername(String proxyUsername);

    /**
     * Sets the proxy password used for the configured HTTP proxy.
     *
     * @param proxyPassword the proxy password used for the configured HTTP proxy
     * @return a reference to the current builder for use in method chaining
     */
    B setProxyPassword(String proxyPassword);

    /**
     * Sets the {@code retryMaxAttempts} the verifier will allow when making HTTP requests to the "keys" endpoint.
     *
     * @param retryMaxAttempts The maximum number of times to retry HTTP requests
     * @return a reference to the current builder for use in method chaining
     */
    B setRetryMaxAttempts(int retryMaxAttempts);

    /**
     * Sets the {@code retryMaxElapsed} the verifier will allow when making HTTP requests to the "keys" endpoint.
     *
     * @param retryMaxElapsed the max duration for the total of HTTP request
     * @return a reference to the current builder for use in method chaining
     */
    B setRetryMaxElapsed(Duration retryMaxElapsed);

    /**
     * Sets the {@code clock} the verifier will use for evaluating token expiration.
     *
     * @param clock specify an alternate clock, such as fixed or offset to be used during testing
     * @return a reference to the current builder for use in method chaining
     */
    B setClock(Clock clock);

    /**
     * Sets the {@code sslFactory} the verifier will use for http client.
     *
     * @param sslFactory the ssl factory instance to be used by the underlying HTTP client.
     * @return a reference to the current builder for use in method chaining
     */
    B setSslFactory(SSLFactory sslFactory);

    /**
     * Sets the {@code preloadSigningKeys} the verifier will use to determine if it needs to prefetch Signing keys into cache at boot time.
     *
     * @param preloadSigningKeys specify if we want to prefetch the signing keys from issuer's url at boot time
     * @return a reference to the current builder for use in method chaining
     */
    B setPreloadSigningKeys(boolean preloadSigningKeys);

    /**
     * Constructs a JWT Verifier.
     * @return A JWT Verifier
     */
    R build();
}
