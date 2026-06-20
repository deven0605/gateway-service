package com.thalicloud.gateway.service;

public interface JwtService {
    /** Returns true if the token signature is valid and the token has not expired. */
    boolean isTokenValid(String token);
}
