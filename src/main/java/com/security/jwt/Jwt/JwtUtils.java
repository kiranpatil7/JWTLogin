package com.security.jwt.Jwt;


import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
    @Value("${spring.app.jwtSecret}")
    private String jwtSecrte;
    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String getJwtFromHeader(HttpServletRequest request){
        String bearToken =request.getHeader("Authorization");
        if(bearToken!=null && bearToken.startsWith("Bearer ")){
            return bearToken.substring(7);
        }
        return null;
    }
    public String generateTokenFromUserName(UserDetails userDetails){
        String userName = userDetails.getUsername();
        return Jwts.builder().subject(userName).issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();
    }

    public String getUserNameFromJwtToken(String token){
        return Jwts.parser().verifyWith((SecretKey) key())
                .build().parseSignedClaims(token).getPayload().getSubject();
    }

    private  SecretKey key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecrte));
    }

    public boolean validateJwtToken(String authToken){
        try{
            Jwts.parser().verifyWith((SecretKey) key())
                    .build().parseSignedClaims(authToken);
            return true;
        }catch (MalformedJwtException e){
            logger.error("InValide JWT Token: {}",e.getMessage());
        }catch (ExpiredJwtException e){
            logger.error("Expired JWT Token: {}",e.getMessage());
        }catch (UnsupportedJwtException e){
            logger.error("Unsupported JWT Token: {}",e.getMessage());
        }catch(IllegalArgumentException e){
            logger.error("JWT claims String empty Token: {}",e.getMessage());
        }
        return  false;
    }

}
