package com.allways.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class AccessTokenDecryptFilter extends AbstractGatewayFilterFactory<AccessTokenDecryptFilter.Config> {

    private String type = "Bearer ";
    @Value("${jwt.key.access}") String key;
    public AccessTokenDecryptFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            // 들어온 요청 헤더에서 accessToken 가져오기
            String accessToken = exchange.getRequest().getHeaders().getFirst("AccessToken");
            System.out.println("AccessToken에 담겨온 내용물 확인");
            System.out.println(accessToken);
//            String refreshToken = exchange.getRequest().getHeaders().getFirst("RefreshToken");

//            validateRefreshToken(refreshToken);

            if(accessToken != null) {
                try {
                    // accessToken 복호화 작업 수행
                    String decodedToken = decryptAccessToken(accessToken);
//                    System.out.println(decodedToken);

                    // 복호화된 토큰을 헤더에 다시 설정
                    exchange.getRequest().mutate().header("userSeq", decodedToken);
                } catch (Exception e) {
                    // 복호화 실패 시 처리할 작업
                    return Mono.error(e);
                }
            }

            // 필터 실행 후 체인 계속 진행
            return chain.filter(exchange);
        };
    }

    private String decryptAccessToken(String accessToken) {
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
