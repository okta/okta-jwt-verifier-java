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
package com.okta.jwt.impl.http

import com.okta.commons.lang.ApplicationInfo
import com.okta.jwt.RestoreSystemProperties
import org.testng.annotations.Listeners
import org.testng.annotations.Test

import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.not
import static org.junit.Assert.assertThat

@Listeners(RestoreSystemProperties.class)
class OktaCommonsHttpClientTest {

    def expectedVersion

    OktaCommonsHttpClientTest() {
        Properties props = new Properties()
        props.load(OktaCommonsHttpClientTest.getResourceAsStream("/" + ApplicationInfo.VERSION_FILE_LOCATION))
        expectedVersion = props.getProperty("okta-jwt-verifier-java")
    }

    @Test
    void validateVersionTest() {
        // make sure the version has been filtered
        assertThat expectedVersion, not(containsString('${project.version}'))
    }

}
