package com.forsrc.oauth2.gateway.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebExchangeDecorator;

import com.netflix.hystrix.exception.HystrixTimeoutException;

import reactor.core.publisher.Mono;

@RestController
public class FallbackController {

    @RequestMapping(value = "/fallback")
    @ResponseStatus
    public Mono<Map<String, Object>> fallback(ServerWebExchange exchange, Throwable throwable) {
        Map<String, Object> result = new HashMap<>(4);
        Exception exception = exchange.getAttribute(ServerWebExchangeUtils.CIRCUITBREAKER_EXECUTION_EXCEPTION_ATTR);
        ServerWebExchange delegate = ((ServerWebExchangeDecorator) exchange).getDelegate();

        result.put("path", delegate.getRequest().getURI());
        result.put("method", delegate.getRequest().getMethodValue());
        if (exception instanceof HystrixTimeoutException) {
            result.put("message", exception.getMessage());
            result.put("exception", "circuitBreakerExecutionException");
        } else if (exception != null) {
            result.put("message", exception.getMessage());
            result.put("exception", exception.getClass());
        } else {
            result.put("message", null);
            result.put("exception", null);
        }
        return Mono.just(result);
    }
}