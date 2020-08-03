package com.forsrc.oauth2.server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
@EnableResourceServer
@Order(2000)
@AutoConfigureAfter(SecurityConfig.class)
public class Oauth2ServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	BCryptPasswordEncoder passwordEncoder;

	@Autowired
	private AuthenticationManager authenticationManager;

    @Override
    public void configure(final AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.tokenKeyAccess("permitAll()")
        			.checkTokenAccess("isAuthenticated()")
        			.allowFormAuthenticationForClients();;
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
       endpoints.authenticationManager(authenticationManager);
    }

    @Override
    public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
    	clients
    		.inMemory()
        	.withClient("forsrc")
        	.secret(passwordEncoder.encode("forsrc"))
        	.authorizedGrantTypes("authorization_code", "client_credentials", "refresh_token", "password", "implicit")
        	.scopes("read", "write", "trust", "openid", "ui")
        	.autoApprove(true) 
        	.redirectUris("http://localhost:22000/login"); 
    }
}