package com.okta.jwt;

import java.time.Instant;
import java.util.Map;

public interface Jwt {

    String getTokenValue();

    Instant getIssuedAt();

    Instant getExpiresAt();

    Map<String, Object> getClaims();
}
