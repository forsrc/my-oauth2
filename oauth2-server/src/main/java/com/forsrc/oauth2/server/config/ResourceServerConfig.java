package com.forsrc.oauth2.server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
@EnableResourceServer
@Order(-10)
@AutoConfigureAfter(SecurityConfig.class)
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {


	@Autowired
    private TokenStore tokenStore;

    @Autowired
    private DefaultTokenServices tokenServices;

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.resourceId("oauth_server")
        		.tokenStore(tokenStore)
        		.tokenServices(tokenServices)
        ;
    }


    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/api/**", "/user/me").authenticated()
                .antMatchers(HttpMethod.GET, "/api/**").access("#oauth2.hasScope('read')")
                .antMatchers(HttpMethod.OPTIONS, "/api/**").access("#oauth2.hasScope('read') or #oauth2.hasScope('write')")
                .antMatchers(HttpMethod.POST, "/api/**").access("#oauth2.hasScope('write')")
                .antMatchers(HttpMethod.PUT, "/api/**").access("#oauth2.hasScope('write')")
                .antMatchers(HttpMethod.PATCH, "/api/**").access("#oauth2.hasScope('write')")
                .antMatchers(HttpMethod.DELETE, "/api/**").access("#oauth2.hasScope('write')")

        ;


//        http.authorizeRequests()
//                .antMatchers("/actuator/**")
//                .permitAll()
//        ;
    }
}