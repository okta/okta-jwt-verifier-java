package com.okta.jwt.example;

import com.okta.jwt.Jwt;
import com.okta.jwt.JwtHelper;
import com.okta.jwt.JwtVerifier;

public class QuickStartExample {

    public static void main(String[] args) throws Exception {

        if (args == null || args.length != 3) {
            System.err.println("Usage: "+ QuickStartExample.class.getName() +" [issuerUrl] [clientId] [jwtString]");
            System.exit(1);
        }

        String issuerUrl = args[0];
        String clientId  = args[1];
        String jwtString = args[2];


        // 1. build the parser
        JwtVerifier jwtVerifier = new JwtHelper()
                                    .setIssuerUrl(issuerUrl)
                                    .setClientOrAudience(clientId)
                                    .build();

        // 2. Process the token (includes validation)
        Jwt jwt = jwtVerifier.decodeAccessToken(jwtString);

        // 3. Do something with the token
        System.out.println(jwt.getTokenValue()); // print the token
        System.out.println(jwt.getClaims().get("invalidKey")); // an invalid key just returns null
        System.out.println(jwt.getClaims().get("groups")); // handle an array value
        System.out.println(jwt.getExpiresAt()); // print the expiration time
    }
}
