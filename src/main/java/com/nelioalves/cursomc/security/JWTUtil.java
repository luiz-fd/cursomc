package com.nelioalves.cursomc.security;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

@Component
public class JWTUtil {

	@Value("${jwt.secret}")
	private String secret;

	@Value("${jwt.expiration}")
	private Long expiration;
/*
	@Deprecated
	public String generateToken(String username) {
		return Jwts.builder()
				.setSubject(username)
				.setExpiration(new Date(System.currentTimeMillis() + expiration))
				//.sign(Algorithm.HMAC512(secret.getBytes(StandardCharsets.UTF_8)));
				.signWith(SignatureAlgorithm.HS512, secret.getBytes())
				.compact();
	}*/
	
	public String generateToken(String username) {
	    return JWT.create()
	           .withSubject(username)
	           .withExpiresAt(new Date(System.currentTimeMillis() + expiration))
	           .sign(Algorithm.HMAC512(secret.getBytes(StandardCharsets.UTF_8)));
	}
}