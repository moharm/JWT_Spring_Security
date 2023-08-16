package com.moharm.security.config;

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

@Service
public class JwtService {


  public static final String SECRET_KEY = "87774029bcb86ffe95b6c63dca5427425746829a3d74f24650ac4c53af0b767a";

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
    byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
    return Keys.hmacShaKeyFor(keyBytes);
  }

}
