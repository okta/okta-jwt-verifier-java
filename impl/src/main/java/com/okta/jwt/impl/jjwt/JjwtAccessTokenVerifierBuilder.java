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

import com.okta.jwt.AccessTokenVerifier;
import com.okta.jwt.impl.Assert;

/**
 * Classes in this `impl` implementation package may change in NON backward compatible way, and should ONLY be used as
 * a "runtime" dependency.
 */
public final class JjwtAccessTokenVerifierBuilder extends BaseVerifierBuilderSupport<AccessTokenVerifier.Builder, AccessTokenVerifier>
                                                  implements AccessTokenVerifier.Builder {

    private String audience = "api://default";

    public AccessTokenVerifier.Builder setAudience(String audience) {
        Assert.notNull(audience, "audience cannot be null");
        this.audience = audience;
        return this;
    }

    @Override
    protected void validate() {
        super.validate();
        if (audience == null || audience.isEmpty()) {
            throw new IllegalArgumentException("audience cannot be null or empty");
        }
    }

    @Override
    public AccessTokenVerifier build() {
        validate();
        return new JjwtAccessTokenVerifier(getIssuer(), audience, getLeeway(), signingKeyResolver());
    }
}