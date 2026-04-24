package com.simplejwtauth.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hazelcast.config.Config;
import com.hazelcast.config.IndexConfig;
import com.hazelcast.config.IndexType;
import com.hazelcast.config.MapConfig;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.spring.cache.HazelcastCacheManager;
import com.simplejwtauth.auth.adapter.in.web.OAuthController;
import com.simplejwtauth.auth.adapter.in.web.LoginController;
import com.simplejwtauth.auth.adapter.out.google.GoogleOAuthClient;
import com.simplejwtauth.auth.adapter.out.hazelcast.HazelcastOAuthCodeStore;
import com.simplejwtauth.auth.adapter.out.hazelcast.HazelcastOAuthStateStore;
import com.simplejwtauth.auth.adapter.out.hazelcast.HazelcastRefreshTokenStore;
import com.simplejwtauth.auth.adapter.out.oauth.RoutingOAuthClient;
import com.simplejwtauth.auth.application.config.JwtSettings;
import com.simplejwtauth.auth.application.config.OAuthGoogleSettings;
import com.simplejwtauth.auth.application.config.SecuritySettings;
import com.simplejwtauth.auth.application.config.WebSettings;
import com.simplejwtauth.auth.application.port.in.LoginUseCase;
import com.simplejwtauth.auth.application.port.in.OAuthLoginUseCase;
import com.simplejwtauth.auth.application.port.out.JwksProvider;
import com.simplejwtauth.auth.application.port.out.OAuthClient;
import com.simplejwtauth.auth.application.port.out.OAuthCodeStore;
import com.simplejwtauth.auth.application.port.out.OAuthStateStore;
import com.simplejwtauth.auth.application.port.out.OAuthUserResolver;
import com.simplejwtauth.auth.application.port.out.PasswordVerifier;
import com.simplejwtauth.auth.application.port.out.RefreshTokenStore;
import com.simplejwtauth.auth.application.service.LoginApplicationService;
import com.simplejwtauth.auth.application.service.OAuthApplicationService;
import com.simplejwtauth.auth.application.service.TokenIssuer;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.FilterType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@AutoConfiguration
@EnableConfigurationProperties(AuthProperties.class)
@EnableCaching
@ComponentScan(
        basePackages = "com.simplejwtauth.auth",
        excludeFilters = @ComponentScan.Filter(
                type = FilterType.ASSIGNABLE_TYPE,
                classes = {LoginController.class, OAuthController.class}
        )
)
@ConditionalOnProperty(prefix = "simple-jwt-auth", name = "enabled", havingValue = "true", matchIfMissing = true)
public class AuthAutoConfiguration {

    @Bean
    JwtSettings sjaJwtSettings(AuthProperties properties) {
        var jwt = properties.jwt();
        return new JwtSettings(
                jwt.secret(),
                jwt.accessTokenExpiry(),
                jwt.refreshTokenExpiry(),
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
    SecuritySettings sjaSecuritySettings(AuthProperties properties) {
        var sec = properties.security();
        return new SecuritySettings(
                SecuritySettings.Policy.valueOf(sec.defaultPolicy().name()),
                sec.publicPaths()
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

        // Central TTL policy — single source of truth for every IMap this library owns.
        config.addMapConfig(new MapConfig("simple-jwt-auth:rt-hash")
                .setTimeToLiveSeconds(refreshTtlSec));
        config.addMapConfig(new MapConfig("simple-jwt-auth:rt-family-current")
                .setTimeToLiveSeconds(refreshTtlSec));
        config.addMapConfig(new MapConfig("simple-jwt-auth:rt-family-hashes")
                .setTimeToLiveSeconds(refreshTtlSec)
                .addIndexConfig(new IndexConfig(IndexType.HASH, "__key.familyId")));
        config.addMapConfig(new MapConfig("simple-jwt-auth:rt-user-families")
                .setTimeToLiveSeconds(refreshTtlSec)
                .addIndexConfig(new IndexConfig(IndexType.HASH, "__key.userId")));
        config.addMapConfig(new MapConfig("simple-jwt-auth:oauth-state").setTimeToLiveSeconds(600));   // 10m CSRF window
        config.addMapConfig(new MapConfig("simple-jwt-auth:oauth-code").setTimeToLiveSeconds(60));     // 60s handoff
        config.addMapConfig(new MapConfig("sja:google-jwks").setTimeToLiveSeconds(3600));              // 1h JWKS cache

        return Hazelcast.getOrCreateHazelcastInstance(config);
    }

    @Bean(name = "sjaCacheManager")
    @ConditionalOnMissingBean(name = "sjaCacheManager")
    CacheManager sjaCacheManager(HazelcastInstance hazelcastInstance) {
        return new HazelcastCacheManager(hazelcastInstance);
    }

    @Bean
    @ConditionalOnMissingBean
    RefreshTokenStore sjaRefreshTokenStore(HazelcastInstance hazelcastInstance) {
        return new HazelcastRefreshTokenStore(hazelcastInstance);
    }

    @Bean
    @ConditionalOnMissingBean(name = "sjaWebMvcConfigurer")
    WebMvcConfigurer sjaWebMvcConfigurer(AuthInterceptor authInterceptor) {
        return new WebMvcConfig(authInterceptor);
    }

    /** Local login path — active only when a PasswordVerifier is provided. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnBean(PasswordVerifier.class)
    static class LoginConfig {

        @Bean
        LoginApplicationService sjaLoginService(PasswordVerifier verifier, TokenIssuer tokenIssuer) {
            return new LoginApplicationService(verifier, tokenIssuer);
        }

        @Bean
        LoginController sjaLoginController(LoginUseCase loginUseCase,
                                           com.simplejwtauth.auth.adapter.in.web.CookieHelper cookieHelper) {
            return new LoginController(loginUseCase, cookieHelper);
        }
    }

    /** OAuth path — active only when an OAuthUserResolver is provided. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnBean(OAuthUserResolver.class)
    static class OAuthConfig {

        @Bean
        OAuthGoogleSettings sjaGoogleSettings(AuthProperties properties) {
            var oauth = properties.oauth();
            var g = oauth != null ? oauth.google() : null;
            if (g == null) {
                throw new IllegalStateException(
                        "OAuthUserResolver is present but simple-jwt-auth.oauth.google.* is not configured");
            }
            return new OAuthGoogleSettings(g.clientId(), g.clientSecret(), g.redirectUri());
        }

        @Bean(name = "sjaOAuthRestClient")
        @ConditionalOnMissingBean(name = "sjaOAuthRestClient")
        RestClient sjaOAuthRestClient() {
            SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
            factory.setConnectTimeout(5000);
            factory.setReadTimeout(5000);
            return RestClient.builder().requestFactory(factory).build();
        }

        @Bean
        @ConditionalOnMissingBean
        JwksProvider sjaGoogleJwksProvider(@Qualifier("sjaOAuthRestClient") RestClient restClient,
                                              ObjectMapper objectMapper) {
            return new com.simplejwtauth.auth.adapter.out.google.GoogleJwksProvider(restClient, objectMapper);
        }

        @Bean
        GoogleOAuthClient googleOAuthClient(OAuthGoogleSettings settings,
                                            @Qualifier("sjaOAuthRestClient") RestClient restClient,
                                            ObjectMapper objectMapper,
                                            JwksProvider jwksProvider) {
            return new GoogleOAuthClient(settings, restClient, objectMapper, jwksProvider);
        }

        @Bean
        @ConditionalOnMissingBean(OAuthClient.class)
        OAuthClient sjaOAuthClient(GoogleOAuthClient google) {
            return new RoutingOAuthClient(google);
        }

        @Bean
        @ConditionalOnMissingBean
        OAuthStateStore sjaOAuthStateStore(HazelcastInstance hazelcastInstance) {
            return new HazelcastOAuthStateStore(hazelcastInstance);
        }

        @Bean
        @ConditionalOnMissingBean
        OAuthCodeStore sjaOAuthCodeStore(HazelcastInstance hazelcastInstance) {
            return new HazelcastOAuthCodeStore(hazelcastInstance);
        }

        @Bean
        OAuthApplicationService sjaOAuthService(
                OAuthUserResolver resolver,
                OAuthClient oAuthClient,
                OAuthStateStore stateStore,
                OAuthCodeStore codeStore,
                TokenIssuer tokenIssuer) {
            return new OAuthApplicationService(resolver, oAuthClient, stateStore, codeStore, tokenIssuer);
        }

        @Bean
        OAuthController sjaOAuthController(OAuthLoginUseCase useCase,
                                              com.simplejwtauth.auth.adapter.in.web.CookieHelper cookieHelper,
                                              WebSettings webSettings) {
            return new OAuthController(useCase, cookieHelper, webSettings);
        }
    }
}
