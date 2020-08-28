package com.springboot.jwt.constants;

public class AuthenticationConstants {

    private AuthenticationConstants(){}

    /**
     * Authorization Token Validation Constants
     */
    public static final String AUTHORIZATION = "Authorization";
    public static final String TOKEN_NOT_PRESENT = "Token Not Present";
    public static final String AUTHORIZATION_TYPE = "Bearer";
    public static final String INVALID_TOKEN = "Token of not type Bearer";

    /**
     * Keystore Constants
     */
    public static final String FROM_KEYSTORE = " from keystore ";
}
