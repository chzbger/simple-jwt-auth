package com.simplejwtauth.common;

import com.hazelcast.config.Config;
import com.hazelcast.config.MapConfig;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.simplejwtauth.auth.adapter.out.hazelcast.HazelcastAuthorizationRequestRepository;
import com.simplejwtauth.auth.adapter.out.hazelcast.HazelcastRefreshTokenStore;
import com.simplejwtauth.auth.application.config.JwtSettings;
import com.simplejwtauth.auth.application.config.WebSettings;
import com.simplejwtauth.auth.application.port.out.RefreshTokenStore;
import com.simplejwtauth.common.security.SecurityConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@AutoConfiguration
@EnableConfigurationProperties(AuthProperties.class)
@Import(SecurityConfig.class)
@ComponentScan(basePackages = "com.simplejwtauth.auth")
public class AuthAutoConfiguration {

    @Bean
    JwtSettings sjaJwtSettings(AuthProperties properties) {
        var jwt = properties.jwt();
        return new JwtSettings(
                jwt.secret(),
                jwt.accessTokenExpiry(),
                jwt.refreshTokenExpiry(),
                jwt.sessionMaxLifetime(),
                jwt.clockSkew()
        );
    }

    @Bean
    WebSettings sjaWebSettings(AuthProperties properties) {
        var web = properties.web();
        return new WebSettings(
                web.basePath(),
                web.cookieName(),
                web.cookieSecure(),
                web.cookieSameSite(),
                web.postLoginRedirect(),
                web.postLoginErrorRedirect()
        );
    }

    @Bean
    @ConditionalOnMissingBean(HazelcastInstance.class)
    HazelcastInstance sjaHazelcastInstance(AuthProperties properties) {
        int refreshTtlSec = (int) properties.jwt().refreshTokenExpiry().toSeconds();

        Config config = new Config();
        config.setInstanceName("sja-hazelcast");
        config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
        config.getNetworkConfig().getJoin().getTcpIpConfig().setEnabled(false);

        // ttl
        config.addMapConfig(new MapConfig(HazelcastRefreshTokenStore.TOKEN_USER_MAP_NAME).setTimeToLiveSeconds(refreshTtlSec));
        config.addMapConfig(new MapConfig(HazelcastRefreshTokenStore.USER_TOKEN_MAP_NAME).setTimeToLiveSeconds(refreshTtlSec));
        config.addMapConfig(new MapConfig(HazelcastAuthorizationRequestRepository.MAP_NAME).setTimeToLiveSeconds(600)); // 10m

        return Hazelcast.getOrCreateHazelcastInstance(config);
    }

    @Bean
    @ConditionalOnMissingBean(JwtDecoder.class)
    JwtDecoder sjaJwtDecoder(JwtSettings settings) {
        SecretKey key = new SecretKeySpec(settings.secret().getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(key)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
        decoder.setJwtValidator(new JwtTimestampValidator(settings.clockSkew()));
        return decoder;
    }

    @Bean
    @ConditionalOnMissingBean(JwtEncoder.class)
    JwtEncoder sjaJwtEncoder(JwtSettings settings) {
        SecretKey key = new SecretKeySpec(settings.secret().getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        return new NimbusJwtEncoder(new ImmutableSecret<>(key));
    }

    @Bean
    @ConditionalOnMissingBean
    RefreshTokenStore sjaRefreshTokenStore(HazelcastInstance hazelcastInstance, JwtSettings settings) {
        return new HazelcastRefreshTokenStore(hazelcastInstance, settings.sessionMaxLifetime());
    }
}
