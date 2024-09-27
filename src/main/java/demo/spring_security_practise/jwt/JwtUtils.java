package demo.spring_security_practise.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header: {}", bearerToken);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // Remove Bearer prefix
        }
        return null;
    }

    public String generateTokenFromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();
        return Jwts.builder()
                .setSubject(username)  // Fix: Pass the username as the subject
                .setIssuedAt(new Date())  // Correct method name is setIssuedAt
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))  // Correct method name is setExpiration
                .signWith(key())  // Assuming key() provides a valid signing key
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key())  // Set the signing key
                .build()
                .parseClaimsJws(token)  // Parse the token and get claims
                .getBody()
                .getSubject();  // Extract the subject (username) from the claims
    }


    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));  // jwtSecret should be a valid Base64 encoded string
    }


    public boolean validateJwtToken(String authToken) {
        try {
            System.out.println("Validate");
            Jwts.parserBuilder()
                    .setSigningKey(key())  // Set the signing key for verification
                    .build()
                    .parseClaimsJws(authToken);  // Parse the token to verify its signature and validity
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

}
