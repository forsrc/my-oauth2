package com.forsrc.oauth2.server.config;


import java.util.concurrent.TimeUnit;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.transaction.annotation.Transactional;

@Configuration
@EnableAuthorizationServer
@Import(AuthorizationServerEndpointsConfiguration.class)
@Order(2)
@AutoConfigureAfter(SecurityConfig.class)
public class Oauth2ServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private AuthenticationManager authenticationManager;


    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        // @formatter:off
        security
                .passwordEncoder(passwordEncoder)
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("permitAll()")
                .allowFormAuthenticationForClients();
        ;
        // @formatter:on
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // @formatter:off
        endpoints.authorizationCodeServices(authorizationCodeServices())
                .authenticationManager(authenticationManager)
                .tokenStore(tokenStore())
        ;
        // @formatter:off
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients)
            throws Exception {
        // @formatter:offs

        JdbcClientDetailsService clientDetailsService = new JdbcClientDetailsService(dataSource);
        clientDetailsService.setPasswordEncoder(passwordEncoder);
        clients.withClientDetails(clientDetailsService);


        // @formatter:on

    }

    @Bean
    public JdbcTokenStore tokenStore() {
        return new MyJdbcTokenStore(dataSource);
    }

    @Bean
    public ApprovalStore approvalStore() throws Exception {
        TokenApprovalStore store = new TokenApprovalStore();
        store.setTokenStore(tokenStore());
        return store;
    }

    @Bean
    public ClientDetailsService clientDetails() {
        return new JdbcClientDetailsService(dataSource);
    }

    @Bean
    protected AuthorizationCodeServices authorizationCodeServices() {
        return new JdbcAuthorizationCodeServices(dataSource);
    }

    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new MyTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        defaultTokenServices.setSupportRefreshToken(true);
        return defaultTokenServices;
    }


    static class MyTokenServices extends DefaultTokenServices {

        private TokenStore tokenStore;

        @Override
        @Transactional
        public synchronized OAuth2AccessToken createAccessToken(OAuth2Authentication authentication)
                throws AuthenticationException {
            try {
                return super.createAccessToken(authentication);
            } catch (Exception e) {
                OAuth2AccessToken existingAccessToken = tokenStore.getAccessToken(authentication);
                if (existingAccessToken != null) {
                    tokenStore.removeAccessToken(existingAccessToken);
                }
                try {
                    TimeUnit.SECONDS.sleep(1);
                } catch (InterruptedException e1) {
                }
                return super.createAccessToken(authentication);
            }

        }

        @Override
        @Transactional(noRollbackFor = {InvalidTokenException.class, InvalidGrantException.class})
        public synchronized OAuth2AccessToken refreshAccessToken(String refreshTokenValue, TokenRequest tokenRequest)
                throws AuthenticationException {
            return super.refreshAccessToken(refreshTokenValue, tokenRequest);
        }

        @Override
        public void setTokenStore(TokenStore tokenStore) {
            super.setTokenStore(tokenStore);
            this.tokenStore = tokenStore;
        }
    }

    static class MyJdbcTokenStore extends JdbcTokenStore {
        private static final Logger LOG = LoggerFactory.getLogger(MyJdbcTokenStore.class);

        public MyJdbcTokenStore(DataSource dataSource) {
            super(dataSource);
        }

        @Override
        public OAuth2AccessToken readAccessToken(String tokenValue) {
            OAuth2AccessToken accessToken = null;

            try {
                accessToken = new DefaultOAuth2AccessToken(tokenValue);
            } catch (EmptyResultDataAccessException e) {
                if (LOG.isInfoEnabled()) {
                    LOG.info("Failed to find access token for token " + tokenValue);
                }
            } catch (IllegalArgumentException e) {
                LOG.warn("Failed to deserialize access token for " + tokenValue, e);
                removeAccessToken(tokenValue);
            }

            return accessToken;
        }
    }


}