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


import com.okta.commons.lang.Assert;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.IncorrectClaimException;
import io.jsonwebtoken.Jws;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@FunctionalInterface
interface ClaimsValidator {

    void validateClaims(Jws<Claims> jws);

    static ClaimsValidator compositeClaimsValidator(ClaimsValidator... claimsValidators) {
        return new CompositeClaimsValidator(Arrays.stream(claimsValidators).collect(Collectors.toSet()));
    }

    final class CompositeClaimsValidator implements ClaimsValidator {

        private final Set<ClaimsValidator> claimsValidators = new HashSet<>();

        CompositeClaimsValidator(Set<ClaimsValidator> claimsValidators) {
            this.claimsValidators.addAll(claimsValidators);
        }

        @Override
        public void validateClaims(Jws<Claims> jws) {
            claimsValidators.forEach(claimsValidator -> claimsValidator.validateClaims(jws));
        }
    }

    final class ContainsAudienceClaimsValidator implements ClaimsValidator {

        private final String expectedAudience;

        ContainsAudienceClaimsValidator(String expectedAudience) {
            Assert.notNull(expectedAudience, "expectedAudience cannot be null");
            this.expectedAudience = expectedAudience;
        }

        @Override
        public void validateClaims(Jws<Claims> jws) {
            Object actual = jws.getBody().get("aud");
            if (!(actual instanceof Collection && ((Collection<?>) actual).contains(expectedAudience)
                || actual instanceof String && actual.equals(expectedAudience))) {
                throw new IncorrectClaimException(jws.getHeader(), jws.getBody(), "Claim `aud` was invalid, it did not contain the expected value of: "+ expectedAudience);
            }
        }
    }
}
