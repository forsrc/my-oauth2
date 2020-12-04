package com.forsrc.oauth2.eureka;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;
import org.springframework.cloud.netflix.hystrix.EnableHystrix;
import org.springframework.cloud.netflix.hystrix.dashboard.EnableHystrixDashboard;

@EnableEurekaServer
@EnableDiscoveryClient
@EnableEurekaClient
@EnableHystrixDashboard
@EnableHystrix
@SpringBootApplication
public class Oauth2EurekaServer {


    public static void main(String[] args) {
        SpringApplication.run(Oauth2EurekaServer.class, args);
    }

}
