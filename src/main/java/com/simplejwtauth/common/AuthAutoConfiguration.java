package com.simplejwtauth.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hazelcast.config.Config;
import com.hazelcast.config.MapConfig;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.simplejwtauth.auth.adapter.in.web.CookieHelper;
import com.simplejwtauth.auth.adapter.out.hazelcast.HazelcastAuthorizationRequestRepository;
import com.simplejwtauth.auth.adapter.out.hazelcast.HazelcastOAuthCodeStore;
import com.simplejwtauth.auth.adapter.out.hazelcast.HazelcastRefreshTokenStore;
import com.simplejwtauth.auth.application.config.JwtSettings;
import com.simplejwtauth.auth.application.config.WebSettings;
import com.simplejwtauth.auth.application.port.out.OAuthCodeStore;
import com.simplejwtauth.auth.application.port.out.OAuthUserResolver;
import com.simplejwtauth.auth.application.port.out.RefreshTokenStore;
import com.simplejwtauth.auth.application.service.TokenIssuer;
import com.simplejwtauth.common.security.OAuth2LoginFailureHandler;
import com.simplejwtauth.common.security.OAuth2LoginSuccessHandler;
import com.simplejwtauth.common.security.SecurityConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@AutoConfiguration
@EnableConfigurationProperties(AuthProperties.class)
@Import(SecurityConfig.class)
@ComponentScan(basePackages = "com.simplejwtauth.auth")
@ConditionalOnProperty(prefix = "simple-jwt-auth", name = "enabled", havingValue = "true", matchIfMissing = true)
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

        // 라이브러리가 사용하는 모든 IMap 의 TTL 을 이 한 곳에서 관리.
        config.addMapConfig(new MapConfig("simple-jwt-auth:rt-token-user")
                .setTimeToLiveSeconds(refreshTtlSec));
        config.addMapConfig(new MapConfig("simple-jwt-auth:rt-user-token")
                .setTimeToLiveSeconds(refreshTtlSec));
        config.addMapConfig(new MapConfig("simple-jwt-auth:oauth-authz-request").setTimeToLiveSeconds(600)); // 10m OAuth flow window
        config.addMapConfig(new MapConfig("simple-jwt-auth:oauth-code").setTimeToLiveSeconds(60));           // 60s sja_code 핸드오프

        return Hazelcast.getOrCreateHazelcastInstance(config);
    }

    /** 자체 발급 access token 용 HS256 decoder. resource server 필터가 이걸로 검증. */
    @Bean
    @ConditionalOnMissingBean(JwtDecoder.class)
    JwtDecoder sjaJwtDecoder(JwtSettings settings) {
        SecretKey key = new SecretKeySpec(
                settings.secret().getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(key)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
        decoder.setJwtValidator(new JwtTimestampValidator(settings.clockSkew()));
        return decoder;
    }

    // TokenIssuer 가 access token 발급 시 사용하는 HS256 encoder
    @Bean
    @ConditionalOnMissingBean(JwtEncoder.class)
    JwtEncoder sjaJwtEncoder(JwtSettings settings) {
        SecretKey key = new SecretKeySpec(
                settings.secret().getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        return new NimbusJwtEncoder(new ImmutableSecret<>(key));
    }

    @Bean
    @ConditionalOnMissingBean
    RefreshTokenStore sjaRefreshTokenStore(HazelcastInstance hazelcastInstance, JwtSettings settings) {
        return new HazelcastRefreshTokenStore(hazelcastInstance, settings.sessionMaxLifetime());
    }

    // OAuth2/OIDC 빈들 — yml 의 client registration 과 OAuthUserResolver 둘다 등록된 경우만 활성
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnBean({ClientRegistrationRepository.class, OAuthUserResolver.class})
    static class OAuthConfig {

        @Bean
        @ConditionalOnMissingBean(OAuthCodeStore.class)
        OAuthCodeStore sjaOAuthCodeStore(HazelcastInstance hazelcastInstance) {
            return new HazelcastOAuthCodeStore(hazelcastInstance);
        }

        @Bean
        @ConditionalOnMissingBean
        AuthorizationRequestRepository<OAuth2AuthorizationRequest> sjaAuthorizationRequestRepository(
                HazelcastInstance hazelcastInstance) {
            return new HazelcastAuthorizationRequestRepository(hazelcastInstance);
        }

        @Bean
        @ConditionalOnMissingBean
        OAuth2LoginSuccessHandler sjaOAuth2LoginSuccessHandler(OAuthUserResolver resolver,
                                                                TokenIssuer tokenIssuer,
                                                                CookieHelper cookieHelper,
                                                                OAuthCodeStore codeStore,
                                                                WebSettings webSettings) {
            return new OAuth2LoginSuccessHandler(resolver, tokenIssuer, cookieHelper, codeStore, webSettings);
        }

        @Bean
        @ConditionalOnMissingBean
        OAuth2LoginFailureHandler sjaOAuth2LoginFailureHandler(WebSettings webSettings) {
            return new OAuth2LoginFailureHandler(webSettings);
        }
    }
}
