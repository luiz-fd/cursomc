package com.nelioalves.cursomc.security;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

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
		System.out.println(expiration);
		System.out.println("Expira em " + System.currentTimeMillis());
		Date termina = new Date(System.currentTimeMillis() + expiration);
		System.out.println("Data de Expiração " +termina.toString());
	    return JWT.create()
	           .withSubject(username)
	           .withExpiresAt(termina)
	           .sign(Algorithm.HMAC512(secret.getBytes(StandardCharsets.UTF_8)));
	}

	public boolean tokenValido(String token) {
		Claims claims = getClaims(token);
		if (claims != null) {
			String username = claims.getSubject();
			Date expirationDate = claims.getExpiration();
			System.out.println("Expira: " + expirationDate.toString());
			Date now = new Date(System.currentTimeMillis());
			System.out.println("Agora: " + now.toString());
			if (username != null && expirationDate != null && now.before(expirationDate)) {
				return true;
			}
		}
		return false;
	}

	public String getUsername(String token) {
		Claims claims = getClaims(token);
		if (claims != null) {
			return claims.getSubject();
		}
		return null;
	}

	private Claims getClaims(String token) {
		try {
			//return Jwts.parser().setSigningKey(secret.getBytes()).parseClaimsJws(token).getBody();
			return (Claims) Jwts.parserBuilder().setSigningKey(secret.getBytes()).build().parseClaimsJws(token);
		}
		catch (Exception e) {
			return null;
		}
	}
}