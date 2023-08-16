package com.moharm.security.service;

import com.moharm.security.config.JwtService;
import com.moharm.security.model.AuthenticationRequest;
import com.moharm.security.model.AuthenticationResponse;
import com.moharm.security.model.RegisterRequest;
import com.moharm.security.repository.UserRepository;
import com.moharm.security.user.Role;
import com.moharm.security.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;

  private final AuthenticationManager authenticationManager;

  public AuthenticationResponse register(RegisterRequest request) {

    var user = User.builder()
        .email(request.getEmail())
        .firstName(request.getFirstName())
        .lastName(request.getLastName())
        .password(passwordEncoder.encode(request.getPassword()))
        .role(Role.USER)
        .build();

    userRepository.save(user);
    var token = jwtService.generateToken(user);
    return AuthenticationResponse.builder()
        .token(token).build();
  }

  public AuthenticationResponse authenticate(AuthenticationRequest request) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
    var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
    var token = jwtService.generateToken(user);
    return AuthenticationResponse.builder().token(token).build();
  }

}
