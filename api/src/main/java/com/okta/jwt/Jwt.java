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
package com.okta.jwt;

import java.time.Instant;
import java.util.Map;

/**
 * A Jwt object represents the claims Body of a JWT object.
 */
public interface Jwt {

    /**
     * Returns the original string representation of this JWT.
     * @return original JWT string representation
     */
    String getTokenValue();

    /**
     * Returns the `iat` claim value as an {@link Instant}.
     * @return `iat` claim value
     */
    Instant getIssuedAt();

    /**
     * Returns the `exp` claim value as an {@link Instant}.
     * @return `exp` claim value
     */
    Instant getExpiresAt();

    /**
     * Returns the token body clams as Map.
     * @return the token body clams as Map
     */
    Map<String, Object> getClaims();
}