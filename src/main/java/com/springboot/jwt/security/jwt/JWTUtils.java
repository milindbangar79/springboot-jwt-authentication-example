package com.springboot.jwt.security.jwt;


import com.springboot.jwt.exception.ServiceException;
import com.springboot.jwt.security.services.UserDetailsSvcImplementation;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.validation.constraints.NotNull;
import java.security.PrivateKey;
import java.util.Date;
import java.util.UUID;

@Component
public class JWTUtils {

    @Value("${auth.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${auth.app.privateKey.password}")
    private String privateKeyPassword;

    @Value("${auth.app.keyStore.password}")
    private String keyStorePassword;

    @Value("${auth.app.privateKey.alias}")
    private String privateKeyAlias;

    private static final Logger logger = LoggerFactory.getLogger(JWTUtils.class);
    private static final String ENCODED_KEY = "SecretKeyToGenJWTsToGenerateTokenWhichWillBeUsedEventuallyToDecodeAndGetSubject";

    /**
     *
     * @param authentication
     * @return String
     */
    public String generateJwtToken(@NotNull Authentication authentication) {


        UserDetailsSvcImplementation userPrincipal = (UserDetailsSvcImplementation) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .setId(UUID.randomUUID().toString())
                .signWith(SignatureAlgorithm.HS512, ENCODED_KEY.getBytes())
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {

        return Jwts
                .parserBuilder()
                .setSigningKey(ENCODED_KEY.getBytes())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    /**
     *
     * @param authToken
     * @return boolean
     */
    public boolean validateJwtToken(String authToken) {

        try {
            Jws<Claims> jwsString = Jwts
                    .parserBuilder()
                    .setSigningKey(ENCODED_KEY.getBytes())
                    .build()
                    .parseClaimsJws(authToken);

            if(!jwsString.getSignature().isEmpty()){
                return true;
            }

        } catch (SecurityException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    /**
     *
     * @throws ServiceException
     */
    private PrivateKey getKey() throws ServiceException{

        KeyStoreAccessorHelper keyStoreAccessorHelper = new KeyStoreAccessorHelper("",keyStorePassword,privateKeyPassword);
        return keyStoreAccessorHelper.getPrivateKey(privateKeyAlias);
    }

}
