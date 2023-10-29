package com.yehah.gateway.security.filter;

import com.yehah.gateway.security.provider.JwtProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
@RequiredArgsConstructor
public class JwtFilter implements WebFilter {
    private final JwtProvider jwtProvider;
    public static final String HEADER_KEY = "Authorization";
    public static final String PREFIX = "Bearer ";

    private String resolveToken(ServerHttpRequest request) {
        String authToken = request.getHeaders().getFirst(HEADER_KEY);
        if (StringUtils.hasText(authToken) && authToken.startsWith(PREFIX)) {
            return authToken.substring(7);
        }
        return null;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain){
        ServerHttpRequest request = exchange.getRequest();

        String authToken = resolveToken(request); // 인증토큰

        Authentication authentication = null;
        ServerWebExchange serverWebExchange = null;
        if(StringUtils.hasText(authToken)){ // 토큰이 있는 경우
            if(jwtProvider.validToken(authToken)){ // 토큰이 유효한 경우
                authentication = jwtProvider.getAuthentication(authToken);

                SecurityContextHolder.getContext().setAuthentication(authentication);

                String id = authentication.getPrincipal().toString();
                log.info(id);
                serverWebExchange = exchange.mutate()
                        .request(builder -> builder.header("id", id))
                        .build();
            }
        }

        if(authentication != null){
            return chain.filter(serverWebExchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
        }else{
            return chain.filter(exchange);
        }
    }
}
