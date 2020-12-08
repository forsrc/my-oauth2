package com.forsrc.oauth2.gateway.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forsrc.oauth2.gateway.model.GatewayDefine;
import com.forsrc.oauth2.gateway.service.GatewayDefineService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.FilterDefinition;
import org.springframework.cloud.gateway.handler.predicate.PredicateDefinition;
import org.springframework.cloud.gateway.route.RouteDefinition;
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
    public Mono<List<GatewayDefine>> loadRouteDefinitions() {

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
    public Mono<GatewayDefine> save(@RequestBody RouteDefinition route) throws JsonProcessingException {

        GatewayDefine gatewayDefine = new GatewayDefine();
        gatewayDefine.setId(route.getId());
        gatewayDefine.setUri(route.getUri().toString());
        gatewayDefine.setPredicates(objectMapper.writeValueAsString(route.getPredicates()));
        gatewayDefine.setFilters(objectMapper.writeValueAsString(route.getFilters()));
        gatewayDefine = gatewayDefineService.save(gatewayDefine);
        return Mono.just(gatewayDefine);

    }

    @PutMapping
    public Mono<GatewayDefine> update(@RequestBody RouteDefinition route) throws JsonProcessingException {

        GatewayDefine gatewayDefine = new GatewayDefine();
        gatewayDefine.setId(route.getId());
        gatewayDefine.setUri(route.getUri().toString());
        GatewayDefine gd = gatewayDefineService.findById(route.getId());
        gatewayDefine.setVersion(gd.getVersion());
        gatewayDefine.setPredicates(objectMapper.writeValueAsString(route.getPredicates()));
        gatewayDefine.setFilters(objectMapper.writeValueAsString(route.getFilters()));
        gatewayDefineService.update(gatewayDefine);
        return Mono.just(gatewayDefine);

    }

    @DeleteMapping("/{id}")
    public Mono<Void> delete(@PathVariable("id") String id) {
        gatewayDefineService.deleteById(id);
        return Mono.empty();
    }

}
