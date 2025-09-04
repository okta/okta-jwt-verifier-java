[<img src="https://www.okta.com/sites/default/files/Dev_Logo-01_Large-thumbnail.png" align="right" width="256px"/>](https://devforum.okta.com/)
[![Maven Central](https://img.shields.io/maven-central/v/com.okta.jwt/okta-jwt-verifier.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.okta.jwt%22%20a%3A%22okta-jwt-verifier%22)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Support](https://img.shields.io/badge/support-Developer%20Forum-blue.svg)](https://devforum.okta.com/)

# Okta JWT Verifier for Java

As a result of a successful authentication by [obtaining an authorization grant from a user](https://developer.okta.com/docs/api/resources/oauth2.html#obtain-an-authorization-grant-from-a-user) or using the Okta API, you will be 
provided with a signed JWT (`id_token` and/or `access_token`). A common use case for these access tokens is to use it 
inside of the Bearer authentication header to let your application know who the user is that is making the request. In 
order for you to know this use is valid, you will need to know how to validate the token against Okta. This guide gives 
you an example of how to do this using Okta's JWT Validation library for Java.

> If you are validating access tokens from a Spring application take a look at the [Okta Spring Boot Starter](https://github.com/okta/okta-spring-boot).

### Prerequisites

* Java 11 or later

## Things you will need
To validate a JWT, you will need a few different items:

1. Your issuer URL
2. The JWT string you want to verify
3. The Okta JWT Verifier for Java library, for example in your Apache Maven `pom.xml`:

```xml
  <dependency>
    <groupId>com.okta.jwt</groupId>
    <artifactId>okta-jwt-verifier</artifactId>
    <version>${okta-jwt.version}</version>
  </dependency>
  
  <dependency>
    <groupId>com.okta.jwt</groupId>
    <artifactId>okta-jwt-verifier-impl</artifactId>
    <version>${okta-jwt.version}</version>
    <scope>runtime</scope>
  </dependency>
```

# Setting up the Library

The Okta JWT Verifier can created via the fluent `JwtVerifiers` class:

[//]: # (NOTE: code snippets in this README are updated automatically via a Maven plugin by running: mvn okta-code-snippet:snip)
 
[//]: # (method: basicUsage)
```java
// see https://ayza.com/usage.html for detailed usage options
SSLFactory sslFactory = SSLFactory.builder()
        .withIdentityMaterial("identity.jks", "password".toCharArray())
        .withTrustMaterial("truststore.jks", "password".toCharArray())
        .build();
AccessTokenVerifier jwtVerifier = JwtVerifiers.accessTokenVerifierBuilder()
    .setIssuer("https://{yourOktaDomain}/oauth2/default")
    .setAudience("api://default")                   // defaults to 'api://default'
    .setConnectionTimeout(Duration.ofSeconds(1))    // defaults to 1s
    .setRetryMaxAttempts(2)                     // defaults to 2
    .setRetryMaxElapsed(Duration.ofSeconds(10)) // defaults to 10s
    .setSslFactory(sslFactory)
    .build();
```
[//]: # (end: basicUsage)

This helper class configures a JWT parser with the details found through the [OpenID Connect discovery endpoint](https://developer.okta.com/docs/reference/api/oidc/#well-known-openid-configuration). The public keys (JWKS) used to validate the JWTs will also be retrieved 
and cached automatically via blocking calls at startup and whenever the keys are rotated. 

## Validating a JWT

After you have a `JwtVerifier` from the above section and an `access_token` from a successful sign in, or 
from a `Bearer token` in the authorization header, you will need to make sure that it is still valid. 
All you need to do is call the `decode` method (where `jwtString` is your access token in string format).

```java
Jwt jwt = jwtVerifier.decode(jwtString);
```

This will validate your JWT for the following:

- token expiration time
- the time it was issue at
- that the token issuer matches the expected value passed into the above helper
- that the token audience matches the expected value passed into the above helper

The result from the decode method is a `Jwt` object which you can introspect additional claims by calling:

```java
jwt.getClaims().get("aClaimKey");
```

## Conclusion

The above are the basic steps for verifying an access token locally. The steps are not tied directly to a framework so 
you could plug in the `okta-jwt-verifier` into the framework of your choice (Dropwizard, Guice, Servlet API, or JAX-RS).

For more information on this project take a look at the following resources:
- [Javadocs](https://developer.okta.com/okta-jwt-verifier-java/apidocs/)
- [Maven Central](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.okta.jwt%22%20a%3A%22okta-jwt-verifier%22)
- [Working With OAuth 2.0 Tokens](https://developer.okta.com/authentication-guide/tokens/)

# Android

Okta JWT Verifier works with Android API 21+.

[Java 8 library desugaring](https://developer.android.com/studio/write/java8-support#library-desugaring) may be required as Okta JWT Verifier makes use of java 8 features. See the link, or the example below on how to configure it.

```
android {
  defaultConfig {
    // Required when setting minSdkVersion to 20 or lower
    multiDexEnabled true
  }

  compileOptions {
    // Flag to enable support for the new language APIs
    coreLibraryDesugaringEnabled true
    // Sets Java compatibility to Java 8
    sourceCompatibility JavaVersion.VERSION_1_8
    targetCompatibility JavaVersion.VERSION_1_8
  }
  // For Kotlin projects
  kotlinOptions {
    jvmTarget = "1.8"
  }
}

dependencies {
  coreLibraryDesugaring 'com.android.tools:desugar_jdk_libs:1.0.10'
}
```
