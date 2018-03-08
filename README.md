[<img src="https://devforum.okta.com/uploads/oktadev/original/1X/bf54a16b5fda189e4ad2706fb57cbb7a1e5b8deb.png" align="right" width="256px"/>](https://devforum.okta.com/)
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

## Things you will need
For validating a JWT, you will need a few different items:

1. Your issuer URL
2. The JWT string you want to verify
3. The Okta JWT Verifier for Java library, for example in your Apache Maven pom.xml:

```xml
  <dependency>
    <groupId>com.okta.jwt</groupId>
    <artifactId>okta-jwt-verifier</artifactId>
    <version>${okta-jwt.version}</version>
  </dependency>
```

# Setting up the Library

The Okta JWT Verifier can created via a fluent `JwtHelper` class:

```java
JwtVerifier jwtVerifier = new JwtHelper()
    .setIssuerUrl("https://{yourOktaDomain}.com/oauth2/default")
    .setAudience("api://default")  // defaults to 'api://default'
    .setConnectionTimeout(250)     // defaults to 250ms
    .setReadTimeout(250)           // defaults to 250ms
    .setClientId("your_client_id") // optional
    .build();
```

This helper class configures a JWT parser with the details found via the [OpenID Connect discovery endpoint](https://openid.net/specs/openid-connect-discovery-1_0.html).  The public keys used to validate the JWTs will also be retrieved 
and cached automatically.

## Validating a JWT

After you have a `JwtVerifier` from above section and a `access_token` from a successful login, or from the `Bearer token` 
in the authorization header, you will need to make sure that this is still valid. All you need to do is call the 
`decode` method (where `jwtString` is your access token in string format).

```java
Jwt jwt = jwtVerifier.decodeAccessToken(jwtString);
```

This will validate your JWT for the following:

- Token expiration date
- Valid token not before date
- The token issuer matches the expected value passed into the above helper
- The token audience matches the expected value passed into the above helper

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