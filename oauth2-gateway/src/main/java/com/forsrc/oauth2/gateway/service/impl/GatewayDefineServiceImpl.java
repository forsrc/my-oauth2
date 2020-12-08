package com.forsrc.oauth2.gateway.service.impl;

import com.forsrc.oauth2.gateway.dao.GatewayDefineDao;
import com.forsrc.oauth2.gateway.model.GatewayDefine;
import com.forsrc.oauth2.gateway.service.GatewayDefineService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.event.RefreshRoutesEvent;
import org.springframework.cloud.gateway.filter.FilterDefinition;
import org.springframework.cloud.gateway.handler.predicate.PredicateDefinition;
import org.springframework.cloud.gateway.route.RouteDefinition;
import org.springframework.cloud.gateway.route.RouteDefinitionWriter;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
public class GatewayDefineServiceImpl implements GatewayDefineService, ApplicationEventPublisherAware {
    @Autowired
    GatewayDefineDao gatewayDefineDao;


    @Autowired
    private RouteDefinitionWriter routeDefinitionWriter;
    private ApplicationEventPublisher publisher;

    public GatewayDefineServiceImpl() {
    }

    @Override
    public List<GatewayDefine> findAll() {
        return gatewayDefineDao.findAll();
    }

    @Override
    public RouteDefinition toRouteDefinition(GatewayDefine gatewayDefine) {
        RouteDefinition routeDefinition = new RouteDefinition();
        routeDefinition.setId(gatewayDefine.getId());
        try {
            routeDefinition.setUri(new URI(gatewayDefine.getUri()));
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        List<PredicateDefinition> predicateDefinitions = null;

        predicateDefinitions = gatewayDefine.getPredicateDefinition();
        if (predicateDefinitions != null) {
            routeDefinition.setPredicates(predicateDefinitions);
        }
        List<FilterDefinition> filterDefinitions = gatewayDefine.getFilterDefinition();
        if (filterDefinitions != null) {
            routeDefinition.setFilters(filterDefinitions);
        }
        return routeDefinition;
    }

    @Override
    public List<RouteDefinition> getRouteDefinitions() {
        List<GatewayDefine> gatewayDefines = gatewayDefineDao.findAll();
        if (gatewayDefines == null) {
            return Collections.emptyList();
        }
        List<RouteDefinition> list = new ArrayList<>(gatewayDefines.size());
        for (GatewayDefine gatewayDefine : gatewayDefines) {
            RouteDefinition routeDefinition = toRouteDefinition(gatewayDefine);
            list.add(routeDefinition);
        }

        return list;
    }


    @Override
    public List<GatewayDefine> loadRouteDefinitions() {
        List<GatewayDefine> list = findAll();
        for (GatewayDefine gatewayDefine : list) {
            loadRouteDefinition(gatewayDefine);
        }
        return list;
    }

    @Override
    public void loadRouteDefinition(GatewayDefine gatewayDefine) {
        RouteDefinition routeDefinition = toRouteDefinition(gatewayDefine);
        routeDefinitionWriter.save(Mono.just(routeDefinition)).subscribe();
        this.publisher.publishEvent(new RefreshRoutesEvent(this));
    }

    @Override
    public GatewayDefine save(GatewayDefine gatewayDefine) {
        gatewayDefineDao.save(gatewayDefine);
        return gatewayDefine;
    }

    @Override
    public void deleteById(String id) {
        gatewayDefineDao.deleteById(id);
    }

    @Override
    public boolean existsById(String id) {
        return gatewayDefineDao.existsById(id);
    }

    @Override
    public void refreshRoute() {
        publisher.publishEvent(new RefreshRoutesEvent(this));
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }
}