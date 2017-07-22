okta-jwt-verifier-java
======================

JWT wrapper around the Connect2id Nimubs JOSE library, intended to be used to validate Okta's access tokens.

Tokens will be validated for:
* Valid creation date
* Expiration
* Signature
* Valid issuer
* Valid Client/Audience

Basic usage:

``` java
// 1. build the parser
JwtVerifier jwtVerifier = new JwtHelper()
                            .setIssuerUrl("https://dev-123456.oktapreview.com/oauth2/ausar5cbq5TRooicu812")
                            .setClientOrAudience("my-audience")
                            .build();

// 2. Process the token (includes validation)
Jwt jwt = jwtVerifier.decodeAccessToken(jwtString);

// 3. Do something with the token
jwt.getTokenValue(); // print the token
jwt.getClaims().get("invalidKey"); // an invalid key just returns null
(Collection) jwt.getClaims().get("groups"); // handle an array value
jwt.getExpiresAt(); // expiration time
```
