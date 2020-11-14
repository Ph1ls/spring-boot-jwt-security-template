package de.phil.jwt.mongodb.controllers;

import de.phil.jwt.mongodb.models.ERole;
import de.phil.jwt.mongodb.models.Role;
import de.phil.jwt.mongodb.models.User;
import de.phil.jwt.mongodb.payload.request.LoginRequest;
import de.phil.jwt.mongodb.payload.request.SignupRequest;
import de.phil.jwt.mongodb.payload.response.JwtResponse;
import de.phil.jwt.mongodb.payload.response.MessageResponse;
import de.phil.jwt.mongodb.repository.RoleRepository;
import de.phil.jwt.mongodb.repository.UserRepository;
import de.phil.jwt.mongodb.security.jwt.JwtUtils;
import de.phil.jwt.mongodb.security.services.UserDetailsImpl;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

  private final AuthenticationManager authenticationManager;
  private final UserRepository userRepository;
  private final RoleRepository roleRepository;
  private final PasswordEncoder encoder;
  private final JwtUtils jwtUtils;

  public AuthController(final AuthenticationManager authenticationManager, final UserRepository userRepository, final RoleRepository roleRepository, final PasswordEncoder encoder, final JwtUtils jwtUtils) {
    this.authenticationManager = authenticationManager;
    this.userRepository = userRepository;
    this.roleRepository = roleRepository;
    this.encoder = encoder;
    this.jwtUtils = jwtUtils;
  }

  @PostMapping("/signin")
  public ResponseEntity<JwtResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager.authenticate(
      new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);

    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
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
  public ResponseEntity<MessageResponse> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    final ResponseEntity<MessageResponse> userNotAvailableError = isUsernameAndEmailAvailable(signUpRequest);
    if (userNotAvailableError != null) { return userNotAvailableError; }
    List<ERole> requestedRoles = toRoleEnum(signUpRequest.getRoles());
    List<Role> roles = roleRepository.findAllByName(requestedRoles);
    User user = new User(
      signUpRequest.getUsername(),
      signUpRequest.getEmail(),
      encoder.encode(signUpRequest.getPassword()),
      roles
    );
    User createdUser = userRepository.save(user);
// TODO Hier kannst du nochmal checken ob der user auch wirklich erstellt wurde oder ob es ein DB problem gab
    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }

  private List<ERole> toRoleEnum(final Set<String> roles) {
    if(null == roles) return Collections.emptyList();
    return roles.stream()
      .map(ERole::of)
      .collect(Collectors.toList());
  }

  private ResponseEntity<MessageResponse> isUsernameAndEmailAvailable(final SignupRequest signUpRequest) {
    if (Boolean.TRUE.equals(userRepository.existsByUsername(signUpRequest.getUsername()))) {
      return ResponseEntity
        .badRequest()
        .body(new MessageResponse("Error: Username is already taken!"));
    }

    if (Boolean.TRUE.equals(userRepository.existsByEmail(signUpRequest.getEmail()))) {
      return ResponseEntity
        .badRequest()
        .body(new MessageResponse("Error: Email is already in use!"));
    }
    return null;
  }
}
