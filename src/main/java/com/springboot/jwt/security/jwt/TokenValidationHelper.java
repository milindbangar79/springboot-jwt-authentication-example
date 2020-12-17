package com.springboot.jwt.security.jwt;

import com.springboot.jwt.constants.AuthenticationConstants;
import com.springboot.jwt.exception.ServiceException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;


public class TokenValidationHelper {

    private static final Logger log = LogManager.getLogger(TokenValidationHelper.class);

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
            return Arrays.asList(token.split(" ")).get(1);
        } else {
            log.error("Token is not of type bearer");
            throw new ServiceException(AuthenticationConstants.INVALID_TOKEN);
        }
    }
}
