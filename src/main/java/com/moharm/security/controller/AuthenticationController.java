package com.moharm.security.controller;


import com.moharm.security.model.AuthenticationRequest;
import com.moharm.security.model.AuthenticationResponse;
import com.moharm.security.model.RegisterRequest;
import com.moharm.security.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/moharm/auth")
@RequiredArgsConstructor
public class AuthenticationController {


  private final AuthenticationService authenticationService;


  @PostMapping("/register")
  public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request){

    return ResponseEntity.ok(authenticationService.register(request));

  }

  @PostMapping("/authenticate")
  public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request){
    return ResponseEntity.ok(authenticationService.authenticate(request));


  }
}
