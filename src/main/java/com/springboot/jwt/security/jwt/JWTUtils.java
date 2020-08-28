package com.springboot.jwt.security.jwt;


import com.springboot.jwt.exception.ServiceException;
import com.springboot.jwt.security.services.UserDetailsSvcImplementation;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.util.Date;

@Component
@PropertySource("classpath:application.properties")
public class JWTUtils {

    private static final Logger logger = LoggerFactory.getLogger(JWTUtils.class);

    @Value("${auth.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${auth.app.privateKey.password}")
    private String privateKeyPassword;

    @Value("${auth.app.keyStore.password}")
    private String keyStorePassword;

    @Value("${auth.app.privateKey.alias}")
    private String privateKeyAlias;

    /**
     *
     * @param authentication
     * @return
     * @throws ServiceException
     */
    public String generateJwtToken(Authentication authentication) throws ServiceException{


        UserDetailsSvcImplementation userPrincipal = (UserDetailsSvcImplementation) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(getKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    public String getUserNameFromJwtToken(String token) throws ServiceException {
        logger.info("Trying to get the Username");
        return Jwts.parser().setSigningKey(getKey()).parseClaimsJws(token).getBody().getSubject();
    }

    /**
     *
     * @param authToken
     * @return boolean
     */
    public boolean validateJwtToken(String authToken) {

        try {
            Jwts.parser().setSigningKey(getKey()).parseClaimsJws(authToken);
            logger.info("Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken) ::: {} ", Jwts.parser().setSigningKey(getKey()).parseClaimsJws(authToken));
            return true;
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
        } catch (ServiceException e) {
            logger.error("Got Exception while fetching Key with reason :: {} ", e.getCause());
        }

        return false;
    }

    /**
     *
     * @return SecretKey
     * @throws ServiceException
     */
    private PrivateKey getKey() throws ServiceException{

        KeyStoreAccessorHelper keyStoreAccessorHelper = new KeyStoreAccessorHelper("",keyStorePassword,privateKeyPassword);
        return keyStoreAccessorHelper.getPrivateKey(privateKeyAlias);
    }

}
