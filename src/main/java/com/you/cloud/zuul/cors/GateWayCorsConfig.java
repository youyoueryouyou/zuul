package com.you.cloud.zuul.cors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Component
@Configuration
public class GateWayCorsConfig {
    @Bean
    public CorsFilter corsFilter() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        final CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowCredentials(false);// 是否允许cookies跨域
        corsConfiguration.addAllowedHeader("*"); // 允许访问的头信息,*表示全部
        corsConfiguration.addAllowedOrigin("http://localhost:8181"); //允许向该服务器提交请求的URI，*表示全部允许
        corsConfiguration.addAllowedMethod("*"); // 允许提交请求的方法，*表示全部允许
        source.registerCorsConfiguration("/**", corsConfiguration);
        return new CorsFilter(source);
    }

}