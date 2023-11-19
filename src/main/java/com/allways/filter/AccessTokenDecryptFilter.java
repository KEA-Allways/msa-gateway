package com.allways.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class AccessTokenDecryptFilter extends AbstractGatewayFilterFactory<AccessTokenDecryptFilter.Config> {

    private String type = "Bearer ";
    @Value("${jwt.key.access}") String access_key;
    @Value ("${jwt.max-age.access}") long access_maxAgeSeconds;
    @Value ("${jwt.key.refresh}")String refresh_key;
    
    public AccessTokenDecryptFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            // 들어온 요청 헤더에서 accessToken 가져오기
            String accessToken = exchange.getRequest().getHeaders().getFirst("AccessToken");
            String refreshToken = exchange.getRequest().getHeaders().getFirst("RefreshToken");

            System.out.println("--------------------------------------------");
            System.out.println("AccessToken에 담겨온 내용물 확인");
            System.out.println(accessToken);
            System.out.println("RefreshToken에 담겨온 내용물 확인");
            System.out.println(refreshToken);
            System.out.println("--------------------------------------------");

            if(accessToken != null) {
                try {
                    String decodedAccessToken = decryptToken(access_key, accessToken);
//                    System.out.println("accessToken이 만료되지 않았을 경우: ");
//                    System.out.println(decodedAccessToken);

                    // 복호화된 토큰을 헤더에 다시 설정
                    exchange.getRequest().mutate().header("userSeq", decodedAccessToken);
                } catch (Exception e) {
                    String decodedRefreshToken = decryptToken(refresh_key, refreshToken);
//                    System.out.println("accessToken이 만료된 경우 refreshKey의 subject: ");
//                    System.out.println(decodedRefreshToken);
                    
                    // RefreshToken으로부터 뽑아낸 userSeq를 사용하여 새로운 AccessToken 발급
                    String newAccessToken = createToken(access_key, decodedRefreshToken, access_maxAgeSeconds);
                    // 목적지를 향해 가는 헤더에 새로 발급받은 AccessToken을 기존 AccessToken 대신 넣어줌
                    // 원래 명령 수행을 위해 필요로 하던 userSeq도 헤더에 추가
//                    exchange.getRequest().mutate().header("AccessToken", newAccessToken);
//                    exchange.getRequest().mutate().header("userSeq", decodedRefreshToken);
                    exchange.getResponse().getHeaders().add("AcessToken", newAccessToken);
                }
            }

            // 필터 실행 후 체인 계속 진행
            return chain.filter(exchange);
        };
    }

    public String createToken(String encodedKey, String subject, long maxAgeSeconds){
        Date now = new Date();
        return type+ Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime()+maxAgeSeconds*1000L))
                .signWith(SignatureAlgorithm.HS256,encodedKey)
                .compact();
    }

    private String decryptToken(String key, String accessToken) {
        return extractSubjects(key, accessToken);
    }

    public String extractSubjects(String encodedKey,String token){
        return parse(encodedKey,token).getBody().getSubject();
    }

    private Jws<Claims> parse(String key, String token) {
        return Jwts.parser()
                .setSigningKey(key)
                .parseClaimsJws(untype(token));
    }

    private String untype(String token) {
        return token.substring(type.length());
    }

    public static class Config {
        // 필요한 경우 구성을 위한 추가적인 필드 정의
    }
}
