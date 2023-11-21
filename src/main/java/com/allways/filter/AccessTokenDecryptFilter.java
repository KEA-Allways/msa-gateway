package com.allways.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import com.allways.AuthenticationEntryPointException;
import com.allways.TokenHelper;
import com.allways.feign.AccessTokenFeignResponse;
import com.allways.feign.AccessTokenFeignService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AccessTokenDecryptFilter extends AbstractGatewayFilterFactory<AccessTokenDecryptFilter.Config> {

    private String type = "Bearer ";
    // @Autowired
    // private AccessTokenFeignService accessTokenFeignService;
    @Value("${jwt.key.access}") String key;

    static String accessToken;

    private final TokenHelper accessTokenHelper;
    private final TokenHelper refreshTokenHelper;

    public AccessTokenDecryptFilter(TokenHelper accessTokenHelper, TokenHelper refreshTokenHelper) {
        super(Config.class);
        this.accessTokenHelper = accessTokenHelper;
        this.refreshTokenHelper = refreshTokenHelper;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            // 들어온 요청 헤더에서 accessToken 가져오기
            String accessToken = exchange.getRequest().getHeaders().getFirst("AccessToken");
            String refreshToken = exchange.getRequest().getHeaders().getFirst("RefreshToken");

            System.out.println("AccessToken에 담겨온 내용물 확인");
            System.out.println(accessToken);

         // validateRefreshToken(refreshToken);

            if(accessToken != null) {
                try {
                    // accessToken 복호화 작업 수행
                    String userSeq = decryptAccessToken(accessToken,refreshToken);

                    exchange.getRequest().mutate().header("AccessToken", accessToken);
                    // 복호화된 토큰을 헤더에 다시 설정
                    exchange.getRequest().mutate().header("userSeq", userSeq);

                } catch (Exception e) {
                    // 복호화 실패 시 처리할 작업

                    return Mono.error(e);
                }
            }

            // 필터 실행 후 체인 계속 진행
            return chain.filter(exchange);
        };
    }

    private String decryptAccessToken(String accessToken, String refreshToken) {
        return extractSubjects(key, accessToken, refreshToken);
    }

    public String extractSubjects(String encodedKey,String accessToken, String refreshToken){
        return parse(encodedKey,accessToken,refreshToken).getBody().getSubject();
    }

    private Jws<Claims> parse(String key, String token, String refreshToken)  {

        try {
            return Jwts.parser()
                .setSigningKey(key)
                .parseClaimsJws(untype(token));
        } catch (ExpiredJwtException e) {

            //refreshToken이 만료된 경우 로그인페이지로 리다이렉션 하는 코드 작성하기
            // validateRefreshToken(refreshToken);
            String subject = refreshTokenHelper.extractSubject(refreshToken);
            accessToken = accessTokenHelper.createToken(subject);

            return Jwts.parser()
                .setSigningKey(key)
                .parseClaimsJws(untype(accessToken));

        }
    }

    private void validateRefreshToken(String refreshToken) {
        if(!refreshTokenHelper.validate(refreshToken)){
            throw new AuthenticationEntryPointException();
        }
    }

    private String untype(String token) {
        return token.substring(type.length());
    }

    public static class Config {
        // 필요한 경우 구성을 위한 추가적인 필드 정의
    }
}
