package com.forsrc.oauth2.gateway.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.forsrc.oauth2.gateway.model.GatewayDefine;
import com.forsrc.oauth2.gateway.service.GatewayDefineService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.FilterDefinition;
import org.springframework.cloud.gateway.handler.predicate.PredicateDefinition;
import org.springframework.cloud.gateway.route.RouteDefinition;
import org.springframework.cloud.gateway.support.NotFoundException;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/gateway")
public class GatewayController {

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private GatewayDefineService gatewayDefineService;


    @GetMapping("refresh/")
    public Mono<Void> refreshRoute() {
        gatewayDefineService.refreshRoute();
        return Mono.empty();
    }

    @GetMapping("init/")
    public Mono<String> loadRouteDefinitions() {

        return Mono.just(gatewayDefineService.loadRouteDefinitions());
    }

    @GetMapping()
    public Flux<RouteDefinition> getRouteDefinitions() {
        try {
            List<GatewayDefine> gatewayDefineList = gatewayDefineService.findAll();
            Map<String, RouteDefinition> routes = new LinkedHashMap<String, RouteDefinition>();
            for (GatewayDefine gatewayDefine : gatewayDefineList) {
                RouteDefinition definition = new RouteDefinition();
                definition.setId(gatewayDefine.getId());
                definition.setUri(new URI(gatewayDefine.getUri()));
                List<PredicateDefinition> predicateDefinitions = gatewayDefine.getPredicateDefinition();
                if (predicateDefinitions != null) {
                    definition.setPredicates(predicateDefinitions);
                }
                List<FilterDefinition> filterDefinitions = gatewayDefine.getFilterDefinition();
                if (filterDefinitions != null) {
                    definition.setFilters(filterDefinitions);
                }
                routes.put(definition.getId(), definition);

            }
            return Flux.fromIterable(routes.values());
        } catch (Exception e) {
            e.printStackTrace();
            return Flux.empty();
        }
    }


    @PostMapping
    public Mono<Void> save(Mono<RouteDefinition> route) {
        return route.flatMap(r -> {
            try {
                GatewayDefine gatewayDefine = new GatewayDefine();
                gatewayDefine.setId(r.getId());
                gatewayDefine.setUri(r.getUri().toString());
                gatewayDefine.setPredicates(objectMapper.writeValueAsString(r.getPredicates()));
                gatewayDefine.setFilters(objectMapper.writeValueAsString(r.getFilters()));
                gatewayDefineService.save(gatewayDefine);
                return Mono.empty();

            } catch (Exception e) {
                e.printStackTrace();
                return Mono.defer(() -> Mono.error(new NotFoundException("RouteDefinition save error: " + r.getId())));
            }

        });
    }

    @DeleteMapping("/{id}")
    public Mono<Void> delete(@PathVariable("id") Mono<String> routeId) {
        return routeId.flatMap(id -> {
            try {
                gatewayDefineService.deleteById(id);
                return Mono.empty();

            } catch (Exception e) {
                e.printStackTrace();
                return Mono.defer(() -> Mono.error(new NotFoundException("RouteDefinition delete error: " + routeId)));
            }
        });
    }

}
