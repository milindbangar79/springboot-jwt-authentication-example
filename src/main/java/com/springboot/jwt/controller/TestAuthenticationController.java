package com.springboot.jwt.controller;

import com.springboot.jwt.exception.ServiceException;
import com.springboot.jwt.payloads.response.MessageResponse;
import com.springboot.jwt.security.jwt.JWTUtils;
import com.springboot.jwt.security.jwt.TokenValidationHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class TestAuthenticationController {

    @Autowired
    JWTUtils jwtUtils;

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
    public ResponseEntity<MessageResponse> verifyToken(HttpServletRequest httpServletRequest) throws ServiceException {

        String token = TokenValidationHelper.parseAuthorizationHeader(httpServletRequest);

        if(jwtUtils.validateJwtToken(token)){
            return ResponseEntity.ok(new MessageResponse("Token is valid"));
        } else {
            return ResponseEntity.ok(new MessageResponse("Token is invalid"));
        }
    }
}
