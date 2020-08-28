package com.springboot.jwt.controller;

import com.springboot.jwt.exception.ServiceException;
import com.springboot.jwt.security.jwt.TokenValidationHelper;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class TestAuthenticationController {

    @GetMapping("/all")
    public String allAccess() {
        return "Public Content.";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public String userAccess() {
        return "User Content.";
    }

    @GetMapping("/mod")
    @PreAuthorize("hasRole('MODERATOR')")
    public String moderatorAccess() {
        return "Moderator Board.";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return "Admin Board.";
    }

    @PostMapping("/verify")
    public boolean verifyToken(HttpServletRequest httpServletRequest) throws ServiceException {
        String token = TokenValidationHelper.parseAuthorizationHeader(httpServletRequest);
        //TODO : Add login for verifying the JWT token . Only for test purposes
        return true;


    }
}
