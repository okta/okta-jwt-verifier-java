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

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
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
     * Sets the {@code issuer} the verifier will expect.
     *
     * @param readTimeout connection timeout
     * @return a reference to the current builder for use in method chaining
     */
    B setReadTimeout(Duration readTimeout);

    /**
     * Sets the {@code sslSocketFactory} for the verifier.
     *
     * @param sslSocketFactory ssl socket factory
     * @return a reference to the current builder for use in method chaining
     */
    B setSslSocketFactory(SSLSocketFactory sslSocketFactory);

    /**
     * Sets the {@code trustManager} for the verifier.
     *
     * @param trustManager ssl trust manager
     * @return a reference to the current builder for use in method chaining
     */
    B setTrustManager(X509TrustManager trustManager);

    /**
     * Sets the {@code hostnameVerifier} for the verifier.
     *
     * @param hostnameVerifier hostname verifier
     * @return a reference to the current builder for use in method chaining
     */
    B setHostnameVerifier(HostnameVerifier hostnameVerifier);

    /**
     * Constructs a JWT Verifier.
     * @return A JWT Verifier
     */
    R build();
}
