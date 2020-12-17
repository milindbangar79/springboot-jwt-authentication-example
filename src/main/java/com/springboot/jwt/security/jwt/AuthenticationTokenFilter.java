package com.springboot.jwt.security.jwt;

import com.springboot.jwt.exception.ServiceException;
import com.springboot.jwt.services.UserDetailsSvceImpl;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthenticationTokenFilter extends OncePerRequestFilter {

    private static final Logger log = LogManager.getLogger(AuthenticationTokenFilter.class);

    @Autowired
    JWTUtils jwtUtils;

    @Autowired
    UserDetailsSvceImpl userDetailsSvc;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        try {
            String jwt = TokenValidationHelper.parseAuthorizationHeader(httpServletRequest);

            if (StringUtils.isNotEmpty(jwt) && jwtUtils.validateJwtToken(jwt)) {

                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                UserDetails userDetails = userDetailsSvc.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null,
                        userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (ServiceException e) {
            log.error("Cannot set user authentication with exception : {} and cause", e,e.getCause());
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);

    }
}
