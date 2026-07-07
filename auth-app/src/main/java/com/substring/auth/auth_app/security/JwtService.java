package com.substring.auth.auth_app.security;

import com.substring.auth.auth_app.enitites.Role;
import com.substring.auth.auth_app.enitites.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@Getter
@Setter
public class JwtService {
    private final SecretKey key;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;
    private final String issuer;

    public JwtService(
            @Value("${security.jwt.secret}") String secret,
            @Value("${security.jwt.access-ttl-seconds}") long accessTtlSeconds,
            @Value("${security.jwt.refresh-ttl-seconds}") long refreshTtlSeconds,
            @Value("${security.jwt.issuer}") String issuer) {

        if (secret == null || secret.length() < 64) {
            throw new IllegalArgumentException("Invalid Secret");
        }

        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTtlSeconds = accessTtlSeconds;
        this.refreshTtlSeconds = refreshTtlSeconds;
        this.issuer = issuer;
    }

    //Generate Token:
    public String generateTokenAccess(User user) {
        Instant now = Instant.now();
        List<String> roles = user.getRoles() == null ? List.of() :
                user.getRoles().stream().map(Role::getName).toList();

        return Jwts.builder()
                //This is responsible for Payload
                .id(UUID.randomUUID().toString())//Creates random unique identifier for the token OR Sets the JWT ID (jti) claim with a unique value
                .subject(user.getId().toString())//Stores the User identity like (This Token belong to 101 user)
                .issuer(issuer)//Used to verify who issued the token like which services are issued the token
                .issuedAt(Date.from(now))//Indicate when the token is issued
                .expiration(Date.from(now.plusSeconds(accessTtlSeconds)))//this is expired in X(accessTtlSeconds) seconds from now
                .claims(Map.of(
                        "email", user.getEmail(),
                        "roles", roles,
                        "typ", "access"
                ))//This means the JWT carry additional info about the user
                //This is responsible for Header and signature
                .signWith(key, SignatureAlgorithm.HS512).compact();

    }

    //Generate Refresh Token
    public String generateRefreshToken(User user, String jti) {
        Instant now = Instant.now();
        return Jwts.builder()
                .id(jti)//Set JWT ID (Adds unique identifier to the token)
                .subject(user.getId().toString())
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(refreshTtlSeconds)))
                .claim("typ", "refresh")
                .signWith(key, SignatureAlgorithm.HS512)//Creates a Cryptographic signature
                .compact();//Converts everything into a JWT String
    }


    // Parses the JWT token, verifies its signature using the secret key,
    // and extracts the claims (payload data) from the token.
    public Jws<Claims> parse(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
    }
    /*
    Jwts.parser() -> I am preparing to read a token
    .verifyWith(key) -> Is this token really issued by me?
    .build()->  Finalizes the parser configuration
    .parseSignedClaims(token) -> Checks signature using the key, Decodes JWT, Extracts data (claims)
     */
    public boolean isAccessToken(String token) {
        Claims c = parse(token).getPayload();
        return "access".equals(c.get("typ"));
    }

    public boolean isRefreshToken(String token) {
        Claims c = parse(token).getPayload();
        return "refresh".equals(c.get("typ"));
    }

    public UUID getUserId(String token) {
        Claims c = parse(token).getPayload();
        return UUID.fromString(c.getSubject());
    }

    public String getJti(String token) {
        return parse(token).getPayload().getId();
    }

    public List<String> getRoles(String token) {
        Claims c = parse(token).getPayload();
        return (List<String>) c.get("roles");
    }

    public String getEmail(String token){
        Claims c = parse(token).getPayload();
        return (String) c.get("email");
    }
}

