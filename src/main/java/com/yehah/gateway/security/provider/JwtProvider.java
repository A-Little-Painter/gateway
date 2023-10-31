package com.yehah.gateway.security.provider;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Collections;
import java.util.Date;

@Slf4j
@Service
public class JwtProvider {
    @Value("${jwt.secret.key}")
    private String salt;

    private Key SECRET_KEY;

    @PostConstruct
    protected void init(){
        SECRET_KEY = Keys.hmacShaKeyFor(salt.getBytes(StandardCharsets.UTF_8));
    }

    //JWT 토큰 유효성 검증 메서드
    public boolean validToken(String token){
        try{
            Claims claims = getClaims(token);
            //토큰 만료시간 확인
            Date expiration = claims.getExpiration();
            log.info("expiration : " + expiration);
            return !expiration.before(new Date()); //만료시간이 지났으면(true) -> false 반환
        }catch (JwtException | IllegalArgumentException e){
            log.info("validToken error : "+ e.getMessage());
            return false;
        }
    }

    //토큰 기반으로 유저 이메일을 가져오는 메서드
    public String getUserEmailFromToken(String token){
        return getClaims(token).getSubject();
    }

    //토큰 기반으로 인증 정보를 가져오는 메서드
    public Authentication getAuthentication(String token){
        Claims claims = getClaims(token);
        log.info("role : " + claims.get("role"));
        if(claims.get("role") == null) {
            return new UsernamePasswordAuthenticationToken(getUserEmailFromToken(token), null, null);
        } else {
            return new UsernamePasswordAuthenticationToken(getUserEmailFromToken(token), null, Collections.singleton(new SimpleGrantedAuthority(claims.get("role").toString())));
        }
    }

    //토큰에서 claims 추출
    private Claims getClaims(String token) {
        Claims claims;
        try {
            claims = Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException e) {
            log.info("만료된 토큰");
            throw new BadCredentialsException("만료된 토큰", e);
        } catch (MalformedJwtException e) {
            log.info("유효하지 않은 구성의 토큰");
            throw new BadCredentialsException("유효하지 않은 구성의 토큰", e);
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 형식이나 구성의 토큰");
            throw new BadCredentialsException("지원되지 않는 형식이나 구성의 토큰", e);
        } catch (IllegalArgumentException e) {
            log.info("잘못된 입력값");
            throw new BadCredentialsException("잘못된 입력값", e);
        }
        return claims;
    }
}
