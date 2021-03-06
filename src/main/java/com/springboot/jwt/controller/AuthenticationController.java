package com.springboot.jwt.controller;

import com.springboot.jwt.exception.ServiceException;
import com.springboot.jwt.models.Role;
import com.springboot.jwt.models.RoleEnum;
import com.springboot.jwt.models.User;
import com.springboot.jwt.payloads.request.LoginRequest;
import com.springboot.jwt.payloads.request.SignUpRequest;
import com.springboot.jwt.payloads.response.JwtResponse;
import com.springboot.jwt.payloads.response.MessageResponse;
import com.springboot.jwt.repository.RoleRepository;
import com.springboot.jwt.repository.UserRepository;
import com.springboot.jwt.security.jwt.JWTUtils;
import com.springboot.jwt.services.UserDetailsSvcImplementation;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@CrossOrigin(origins = "*", maxAge = 3600)
@RequestMapping("/api/auth")
public class AuthenticationController {

    private static final Logger log = LogManager.getLogger(AuthenticationController.class);

    private static final String EXCEPTION_MESSAGE = "Exception Received While Processing Request {} with exception {}";
    private static final String ERROR_ROLE_IS_NOT_FOUND = "Error: Role is not found.";
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTUtils jwtUtils;

    @Autowired
    public AuthenticationController(final AuthenticationManager authenticationManager, final UserRepository userRepository, final RoleRepository roleRepository, final JWTUtils jwtUtils, final PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.jwtUtils = jwtUtils;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsSvcImplementation userDetails = (UserDetailsSvcImplementation) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<MessageResponse> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) throws ServiceException {

        isUsernameAlreadyInUse(signUpRequest);
        isEmailAlreadyInUse(signUpRequest.getEmail());

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                passwordEncoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRoles();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = checkForRoleTypeAndUpdateUserInformation(RoleEnum.ROLE_USER);
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = null;
                        try {
                            adminRole = checkForRoleTypeAndUpdateUserInformation(RoleEnum.ROLE_ADMIN);
                        } catch (ServiceException e) {
                            log.error(EXCEPTION_MESSAGE, new ServiceException(ERROR_ROLE_IS_NOT_FOUND), e.getMessage());
                        }
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = null;
                        try {
                            modRole = checkForRoleTypeAndUpdateUserInformation(RoleEnum.ROLE_MODERATOR);
                        } catch (ServiceException e) {
                            log.error(EXCEPTION_MESSAGE, new ServiceException(ERROR_ROLE_IS_NOT_FOUND), e.getMessage());
                        }
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = null;
                        try {
                            userRole = checkForRoleTypeAndUpdateUserInformation(RoleEnum.ROLE_USER);
                        } catch (ServiceException e) {
                            log.error(EXCEPTION_MESSAGE, new ServiceException(ERROR_ROLE_IS_NOT_FOUND), e.getMessage());
                        }
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/logout")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public ResponseEntity<MessageResponse> logoutUser() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(null);
        return ResponseEntity.ok(new MessageResponse("logout successful"));
    }

    private void isUsernameAlreadyInUse(SignUpRequest signUpRequest){

        if (Boolean.TRUE.equals(userRepository.existsByUsername(signUpRequest.getUsername()))) {
            ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }
    }

    private void isEmailAlreadyInUse(String email) {
        if (Boolean.TRUE.equals(userRepository.existsByEmail(email))) {
            ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }
    }

    private Role checkForRoleTypeAndUpdateUserInformation(RoleEnum roleEnum) throws ServiceException {
        return roleRepository.findByName(roleEnum)
                .orElseThrow(() -> new ServiceException(ERROR_ROLE_IS_NOT_FOUND));
    }
}
