package com.moharm.security.service;

import io.jsonwebtoken.Claims;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;

@Service
public class JwtService {


  @Value("${application.security.jwt.secret-key}")
  private String secretKey;
  @Value("${application.security.jwt.expiration}")
  private long jwtExpiration;
  @Value("${application.security.jwt.refresh-token.expiration}")
  private long refreshExpiration;
  public String extractUserName(String token) {
    return extarctClaim(token, Claims::getSubject);
  }

  public boolean isTokenValid(String token, UserDetails userDetails ){
    String username = extractUserName(token);
    return username.equals(userDetails.getUsername());
  }

  public boolean isExpiredToken(String token){

    return extractExpiration(token).before(new Date());

  }

  public Date extractExpiration(String token){
    return extarctClaim(token, Claims::getExpiration);
  }

  public String generateToken(UserDetails userDetails){
    return generateToken(new HashMap<>(), userDetails);
  }

  public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails){
    return Jwts.builder().setClaims(extraClaims)
        .setSubject(userDetails.getUsername())
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() * 1000 * 60 * 24))
        .signWith(getSigningKey(), SignatureAlgorithm.HS256)
        .compact();
  }

  public <T> T extarctClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  public Claims extractAllClaims(String token) {
    return Jwts.parserBuilder()
        .setSigningKey(getSigningKey())
        .build()
        .parseClaimsJws(token)
        .getBody();
  }

  public Key getSigningKey() {
    byte[] keyBytes = Decoders.BASE64.decode(secretKey);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  public String generateRefreshToken(
      UserDetails userDetails
  ) {
    return buildToken(new HashMap<>(), userDetails, refreshExpiration);
  }

  private String buildToken(
      Map<String, Object> extraClaims,
      UserDetails userDetails,
      long expiration
  ) {
    return Jwts
        .builder()
        .setClaims(extraClaims)
        .setSubject(userDetails.getUsername())
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + expiration))
        .signWith(getSigningKey(), SignatureAlgorithm.HS256)
        .compact();
  }

  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

}
