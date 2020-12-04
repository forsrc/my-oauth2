package com.forsrc.oauth2.gateway.controller;

import com.netflix.hystrix.exception.HystrixTimeoutException;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebExchangeDecorator;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@RestController
public class FallbackController {

    @RequestMapping(value = "/fallback")
    @ResponseStatus
    public Mono<Map<String, Object>> fallback(ServerWebExchange exchange, Throwable throwable) {
        Map<String, Object> result = new HashMap<>(8);
        ServerHttpRequest request = exchange.getRequest();
        Exception exception = exchange.getAttribute(ServerWebExchangeUtils.HYSTRIX_EXECUTION_EXCEPTION_ATTR);
        ServerWebExchange delegate = ((ServerWebExchangeDecorator) exchange).getDelegate();

        result.put("path", delegate.getRequest().getURI());
        result.put("method", delegate.getRequest().getMethodValue());
        if (exception instanceof HystrixTimeoutException) {
            result.put("message", "HystrixTimeoutException");
        } else if (exception != null && exception.getMessage() != null) {
            result.put("message", exception.getMessage());
        } else {
            result.put("message", null);
        }
        return Mono.just(result);
    }
}