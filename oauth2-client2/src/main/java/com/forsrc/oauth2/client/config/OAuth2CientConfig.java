package com.forsrc.oauth2.client.config;

import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.net.ssl.SSLException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.RemoveAuthorizedClientOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import reactor.netty.http.client.HttpClient;

@Configuration
public class OAuth2CientConfig {

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository, OAuth2AuthorizedClientService clientService) {

        OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials().build();

        AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                clientRegistrationRepository, clientService);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        return authorizedClientManager;
    }

//	@Bean
//	public OAuth2AuthorizedClientManager authorizedClientManager(
//			ClientRegistrationRepository clientRegistrationRepository,
//			OAuth2AuthorizedClientRepository authorizedClientRepository) {
//
//		OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
//				.password().refreshToken().build();
//
//		DefaultOAuth2AuthorizedClientManager result = new DefaultOAuth2AuthorizedClientManager(
//				clientRegistrationRepository, authorizedClientRepository);
//
//		result.setAuthorizationFailureHandler(authorizationFailureHandler(authorizedClientRepository));
//		result.setAuthorizedClientProvider(authorizedClientProvider);
//		result.setContextAttributesMapper(oAuth2AuthorizeRequest -> Stream
//				.of(new String[][] { 
//						{ OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, "forsrc" },
//						{ OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, "forsrc" },
//						})
//				.collect(Collectors.toMap(data -> data[0], data -> data[1])));
//
//		
//		
//		return result;
//	}
//
//	@Bean
//	public OAuth2AuthorizationFailureHandler authorizationFailureHandler(
//			OAuth2AuthorizedClientRepository authorizedClientRepository) {
//		return new RemoveAuthorizedClientOAuth2AuthorizationFailureHandler(
//				(clientRegistrationId, principal, attributes) -> {
//					authorizedClientRepository.removeAuthorizedClient(clientRegistrationId, principal,
//							(HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
//							(HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));
//
//				});
//	}

    @Bean
    public WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) throws SSLException {

        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 = new ServletOAuth2AuthorizedClientExchangeFilterFunction(
                authorizedClientManager);

        oauth2.setDefaultClientRegistrationId("my-oauth2");
        oauth2.setDefaultOAuth2AuthorizedClient(true);


        SslContext sslContext = SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build();
        HttpClient httpClient = HttpClient.create().secure(sslContextSpec -> sslContextSpec.sslContext(sslContext));
        ReactorClientHttpConnector connector = new ReactorClientHttpConnector(httpClient);

        return WebClient.builder()
                .clientConnector(connector)
                .filter(oauth2)
                .apply(oauth2.oauth2Configuration())
                .build();
    }

}
