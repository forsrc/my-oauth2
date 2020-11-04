package com.forsrc.oauth2.resource.server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
@EnableResourceServer
public class Oauth2ResourceServerConfig extends ResourceServerConfigurerAdapter {

//	@Autowired
//	private TokenStore tokenStore;
//
//	@Override
//	public void configure(ResourceServerSecurityConfigurer security) throws Exception {
//		security
//			.resourceId("resource-server")
//			.tokenStore(this.tokenStore);
//	}

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .and()
                    .authorizeRequests()
                    .antMatchers(HttpMethod.GET, "/api/**")
                        .access("#oauth2.hasScope('read')")
                    .antMatchers(HttpMethod.POST, "/api/**")
                        .access("#oauth2.hasScope('write')");
    }
}