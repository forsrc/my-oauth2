package com.forsrc.oauth2.gateway.config;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.NettyDataBuffer;
import org.springframework.core.io.buffer.NettyDataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.netty.buffer.ByteBufAllocator;
import reactor.core.publisher.Mono;

@Configuration
public class GlobalFilterConfig {

	final ObjectMapper mapper = new ObjectMapper();

	@Component
	public static class CachingRequestBodyFilter extends AbstractGatewayFilterFactory<CachingRequestBodyFilter.Config> {

		public CachingRequestBodyFilter() {
			super(CachingRequestBodyFilter.Config.class);
		}

		public GatewayFilter apply(final CachingRequestBodyFilter.Config config) {
			return (exchange, chain) -> ServerWebExchangeUtils.cacheRequestBody(exchange,
					(serverHttpRequest) -> chain.filter(exchange.mutate().request(serverHttpRequest).build()));
		}

		public static class Config {
		}
	}

	@Bean
	@Order(-1)
	public GlobalFilter a() {
		return (exchange, chain) -> {

			ServerHttpRequest request = exchange.getRequest();

			System.out.println(request.getURI() + " -> " + request.getQueryParams() + " -> " + getIpInfo(request));

			if ("POST".equalsIgnoreCase(request.getMethodValue())) {
				Object cachedBody = exchange.getAttribute(ServerWebExchangeUtils.CACHED_REQUEST_BODY_ATTR);
				if (cachedBody instanceof NettyDataBuffer) {
					NettyDataBuffer ndf = (NettyDataBuffer) cachedBody;
					String body = StandardCharsets.UTF_8.decode(ndf.asByteBuffer()).toString();
					if (body.indexOf("{") >= 0 && body.indexOf("}") > 0) {
						TypeReference<HashMap<String, Object>> typeRef = new TypeReference<HashMap<String, Object>>() {
						};

						try {
							HashMap<String, Object> map = mapper.readValue(body, typeRef);

							System.out.println(body + " -> " + map.size());
						} catch (JsonMappingException e) {
							e.printStackTrace();
						} catch (JsonProcessingException e) {
							e.printStackTrace();
						}
					} else {
						System.out.println(body);
					}

				}
			}

			return chain.filter(exchange).then(Mono.fromRunnable(() -> {
			}));
		};
	}

	protected DataBuffer stringBuffer(String value) {
		byte[] bytes = value.getBytes(StandardCharsets.UTF_8);

		NettyDataBufferFactory nettyDataBufferFactory = new NettyDataBufferFactory(ByteBufAllocator.DEFAULT);
		DataBuffer buffer = nettyDataBufferFactory.allocateBuffer(bytes.length);
		buffer.write(bytes);
		return buffer;
	}

	private String getIpInfo(ServerHttpRequest request) {
		StringBuffer ipInfo = new StringBuffer();
		HttpHeaders headers = request.getHeaders();
		String ip = headers.getFirst("x-forwarded-for");
		if (StringUtils.hasText(ip) && !"unknown".equalsIgnoreCase(ip)) {
			ipInfo.append("x-forwarded-for=").append(ip).append(";");
		}

		ip = headers.getFirst("Proxy-Client-IP");
		if (StringUtils.hasText(ip) && !"unknown".equalsIgnoreCase(ip)) {
			ipInfo.append("Proxy-Client-IP=").append(ip).append(";");
		}

		ip = headers.getFirst("WL-Proxy-Client-IP");
		if (StringUtils.hasText(ip) && !"unknown".equalsIgnoreCase(ip)) {
			ipInfo.append("WL-Proxy-Client-IP=").append(ip).append(";");
		}

		ip = headers.getFirst("HTTP_CLIENT_IP");
		if (StringUtils.hasText(ip) && !"unknown".equalsIgnoreCase(ip)) {
			ipInfo.append("HTTP_CLIENT_IP:").append(ip).append(";");
		}

		ip = headers.getFirst("HTTP_X_FORWARDED_FOR");
		if (StringUtils.hasText(ip) && !"unknown".equalsIgnoreCase(ip)) {
			ipInfo.append("HTTP_X_FORWARDED_FOR=").append(ip).append(";");
		}

		ip = headers.getFirst("X-Real-IP");
		if (StringUtils.hasText(ip) && !"unknown".equalsIgnoreCase(ip)) {
			ipInfo.append("X-Real-IP:").append(ip).append(";");
		}

		ip = request.getRemoteAddress().getAddress().getHostAddress();
		if (StringUtils.hasText(ip) && !"unknown".equalsIgnoreCase(ip)) {
			ipInfo.append("getRemoteAddr=").append(ip).append(";");
		}
		return ipInfo.toString();
	}
}
