package com.springboot.jwt.security.jwt;

import com.springboot.jwt.constants.AuthenticationConstants;
import com.springboot.jwt.exception.ServiceException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;


public class TokenValidationHelper {
    private static final Logger log = LoggerFactory.getLogger(TokenValidationHelper.class);

    /**
     * Empty private constructor
     */
    private TokenValidationHelper(){

    }

    public static String parseAuthorizationHeader(HttpServletRequest request) throws ServiceException {

        String token = request.getHeader(AuthenticationConstants.AUTHORIZATION);

        if(StringUtils.isBlank(token)){
            log.error("Token is missing");
            throw new ServiceException(AuthenticationConstants.TOKEN_NOT_PRESENT);
        }

        if(Arrays.asList(token.split(" ")).contains(AuthenticationConstants.AUTHORIZATION_TYPE)){
        } else {
            log.error("Token us not of type bearer");
            throw new ServiceException(AuthenticationConstants.INVALID_TOKEN);
        }

        return Arrays.asList(token.split(" ")).get(1);
    }
}
