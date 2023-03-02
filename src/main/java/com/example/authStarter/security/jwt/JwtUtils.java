package com.example.authStarter.security.jwt;

import com.example.authStarter.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;

@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${springsecurity.app.jwtSecret}")
    private String jwtSecret;

    @Value("${springsecurity.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${springsecurity.app.jwtCookieName}")
    private String jwtCookie;

    //get JWT from cookies by cooke name
    public String getJwtFromCookies(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, null);
        if(cookie != null) {
            return cookie.getValue();
        } else {
            return null;
        }
    }

    //generate response cookie containing JWT from username, data, expiration, secret
    public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal) {
        String jwt = generateTokenFromUsername(userPrincipal.getUsername());
        ResponseCookie cookie = ResponseCookie.from(jwtCookie, jwt).path("/api").maxAge(24*60*60)
                .httpOnly(true).build();
        return cookie;
    }

    // get username from jwt
    public String getUsernameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJwt(token).getBody().getSubject();
    }

    // validate jwt token
    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJwt(authToken);
        } catch( SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch( MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        }  catch( ExpiredJwtException e) {
            logger.error("JWT token expired: {}", e.getMessage());
        }  catch( UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        }  catch( IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    public String generateTokenFromUsername(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date().getTime() + jwtExpirationMs)))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }
}
