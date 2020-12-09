package com.forsrc.oauth2.eureka.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;

import java.util.Collections;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private static final Logger LOGGER = LoggerFactory.getLogger(WebSecurityConfig.class);
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/actuator/**")
                .permitAll()
                .and()
                .requestCache()
                .requestCache(requestCache())
                .and()
                .csrf()
                .disable();
        super.configure(http);

    }


    @Value("${my.gateway-port:#{null}}")
    private String gatewayPort;
    @Value("${my.gateway-port-to-port:#{null}}")
    private String gatewayPortToPort;

    @Bean
    public PortMapper portMapper() {
        PortMapperImpl portMapper = new PortMapperImpl();
        if (gatewayPort != null && gatewayPortToPort != null) {
            LOGGER.info("gateway port to port {}:{}", gatewayPort, gatewayPortToPort);
            portMapper.setPortMappings(Collections.singletonMap(gatewayPort, gatewayPortToPort));
        }
        return portMapper;
    }
    @Bean
    public PortResolver portResolver() {
        PortResolverImpl portResolver = new PortResolverImpl();
        portResolver.setPortMapper(portMapper());
        return portResolver;
    }

    @Bean
    public RequestCache requestCache() {
        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        requestCache.setPortResolver(portResolver());
        return requestCache;
    }

}
