package com.forsrc.oauth2.server.config;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.ApprovalStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.InMemoryApprovalStore;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

@Configuration
@EnableAuthorizationServer
@Import(AuthorizationServerEndpointsConfiguration.class)
@Order(2)
@AutoConfigureAfter(SecurityConfig.class)
public class Oauth2ServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	BCryptPasswordEncoder passwordEncoder;
	
	@Autowired
	private ClientDetailsService clientDetailsService;

	@Autowired
	private AuthenticationManager authenticationManager;

	@ConfigurationProperties(prefix = "security.oauth2.client")
	@Component
	static class MyClientDetails extends BaseClientDetails {

	}

	@Autowired
	MyClientDetails myClientDetails;

    @Override
    public void configure(final AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.tokenKeyAccess("permitAll()")
					.checkTokenAccess("isAuthenticated()")
					.allowFormAuthenticationForClients()
					;
	}

	@SuppressWarnings("deprecation")
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
		endpoints.authenticationManager(authenticationManager)
			//.userApprovalHandler(userApprovalHandler())
			//.accessTokenConverter(jwtAccessTokenConverter())
			//.allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST)
			;
	}

	@SuppressWarnings("deprecation")
	@Override
	public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory()
				.withClient(myClientDetails.getClientId())
				.secret(passwordEncoder.encode(myClientDetails.getClientSecret()))
				.authorizedGrantTypes(myClientDetails.getAuthorizedGrantTypes().stream().toArray(String[]::new))
				.scopes(myClientDetails.getScope().stream().toArray(String[]::new))
				.autoApprove(true)
				.accessTokenValiditySeconds(60)
				.redirectUris(myClientDetails.getRegisteredRedirectUri().stream().toArray(String[]::new))
				;
//    	clients
//    		.inMemory()
//        	.withClient("forsrc")
//        	.secret(passwordEncoder.encode("forsrc"))
//        	.authorizedGrantTypes("authorization_code", "client_credentials", "refresh_token", "password", "implicit")
//        	.scopes("read", "write", "trust", "openid", "ui")
//        	.autoApprove(true) 
//        	.redirectUris("http://localhost:22000/login"); 
	}
	
	//@Bean
	public UserApprovalHandler userApprovalHandler() {
		ApprovalStoreUserApprovalHandler userApprovalHandler = new ApprovalStoreUserApprovalHandler();
		userApprovalHandler.setApprovalStore(approvalStore());
		userApprovalHandler.setClientDetailsService(this.clientDetailsService);
		userApprovalHandler.setRequestFactory(new DefaultOAuth2RequestFactory(this.clientDetailsService));
		return userApprovalHandler;
	}
	
	//@Bean
	public ApprovalStore approvalStore() {
		return new InMemoryApprovalStore();
	}


	//@Bean
	@ConfigurationProperties("jwt")
	JwtAccessTokenConverter jwtAccessTokenConverter() {
		return new JwtAccessTokenConverter();
	}

	@Value("${jwt.verifier-key}")
	String verifierKey;
	@Value("${jwt.signing-key}")
	String signingKey;

	@Bean
	public KeyPair keyPair() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {

		KeyFactory kf = KeyFactory.getInstance("RSA");

		String signing = signingKey.replace("-----BEGIN RSA PRIVATE KEY-----\n", "")
				.replace("-----END RSA PRIVATE KEY-----", "").replaceAll("\n", "");
		String verifier = verifierKey.replace("-----BEGIN PUBLIC KEY-----\n", "")
				.replace("-----END PUBLIC KEY-----", "").replaceAll("\n", "");

		byte[] encodedPrivateKey = Base64.getDecoder().decode(signing);

		ASN1Sequence primitive = (ASN1Sequence) ASN1Sequence.fromByteArray(encodedPrivateKey);
		Enumeration<?> e = primitive.getObjects();
		BigInteger v = ((ASN1Integer) e.nextElement()).getValue();

		int version = v.intValue();
		if (version != 0 && version != 1) {
			throw new IllegalArgumentException("wrong version for RSA private key");
		}
		BigInteger modulus = ((ASN1Integer) e.nextElement()).getValue();
		BigInteger publicExponent = ((ASN1Integer) e.nextElement()).getValue();
		BigInteger privateExponent = ((ASN1Integer) e.nextElement()).getValue();
		BigInteger prime1 = ((ASN1Integer) e.nextElement()).getValue();
		BigInteger prime2 = ((ASN1Integer) e.nextElement()).getValue();
		BigInteger exponent1 = ((ASN1Integer) e.nextElement()).getValue();
		BigInteger exponent2 = ((ASN1Integer) e.nextElement()).getValue();
		BigInteger coefficient = ((ASN1Integer) e.nextElement()).getValue();

		RSAPrivateKeySpec spec = new RSAPrivateKeySpec(modulus, privateExponent);

		PrivateKey privateKey = kf.generatePrivate(spec);
		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(verifier));
		RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
		return new KeyPair(publicKey, privateKey);
	}

	@Bean
	public JWKSet jwkSet() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
		RSAKey.Builder builder = new RSAKey.Builder((RSAPublicKey) keyPair().getPublic()).keyUse(KeyUse.SIGNATURE)
				.algorithm(JWSAlgorithm.RS256).keyID("forsrc");
		return new JWKSet(builder.build());
	}
}