package com.simplejwtauth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.simplejwtauth.adapter.in.web.AuthInterceptor;
import com.simplejwtauth.adapter.in.web.CookieHelper;
import com.simplejwtauth.adapter.in.web.LoginController;
import com.simplejwtauth.adapter.in.web.OAuthController;
import com.simplejwtauth.adapter.in.web.SessionController;
import com.simplejwtauth.adapter.out.google.GoogleOAuthClient;
import com.simplejwtauth.adapter.out.google.HazelcastCachedGoogleJwksProvider;
import com.simplejwtauth.adapter.out.hazelcast.HazelcastOAuthCodeStore;
import com.simplejwtauth.adapter.out.hazelcast.HazelcastOAuthStateStore;
import com.simplejwtauth.adapter.out.hazelcast.HazelcastRefreshTokenStore;
import com.simplejwtauth.adapter.in.web.AuthPolicyAuditor;
import com.simplejwtauth.application.config.JwtSettings;
import com.simplejwtauth.application.config.OAuthGoogleSettings;
import com.simplejwtauth.application.config.SecuritySettings;
import com.simplejwtauth.application.config.WebSettings;
import com.simplejwtauth.application.port.in.LoginUseCase;
import com.simplejwtauth.application.port.in.LogoutUseCase;
import com.simplejwtauth.application.port.in.OAuthLoginUseCase;
import com.simplejwtauth.application.port.in.RefreshUseCase;
import com.simplejwtauth.application.port.out.JwksProvider;
import com.simplejwtauth.application.port.out.OAuthClient;
import com.simplejwtauth.application.port.out.OAuthCodeStore;
import com.simplejwtauth.application.port.out.OAuthStateStore;
import com.simplejwtauth.application.port.out.OAuthUserResolver;
import com.simplejwtauth.application.port.out.PasswordVerifier;
import com.simplejwtauth.application.port.out.RefreshTokenStore;
import com.simplejwtauth.application.service.JwtProvider;
import com.simplejwtauth.application.service.LoginApplicationService;
import com.simplejwtauth.application.service.OAuthApplicationService;
import com.simplejwtauth.application.service.SessionApplicationService;
import com.simplejwtauth.application.service.TokenIssuer;
import com.simplejwtauth.domain.model.OAuthProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

@AutoConfiguration
@EnableConfigurationProperties(AuthProperties.class)
@ConditionalOnProperty(prefix = "simple-jwt-auth", name = "enabled", havingValue = "true", matchIfMissing = true)
public class AuthAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
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
    @ConditionalOnMissingBean
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
    @ConditionalOnMissingBean
    SecuritySettings sjaSecuritySettings(AuthProperties properties) {
        var sec = properties.security();
        return new SecuritySettings(
                SecuritySettings.Policy.valueOf(sec.defaultPolicy().name()),
                sec.publicPaths()
        );
    }

    @Bean
    @ConditionalOnMissingBean(HazelcastInstance.class)
    HazelcastInstance sjaHazelcastInstance() {
        Config config = new Config();
        config.setInstanceName("sja-hazelcast");
        config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
        config.getNetworkConfig().getJoin().getTcpIpConfig().setEnabled(false);
        return Hazelcast.getOrCreateHazelcastInstance(config);
    }

    @Bean
    @ConditionalOnMissingBean
    RefreshTokenStore sjaRefreshTokenStore(HazelcastInstance hazelcastInstance) {
        return new HazelcastRefreshTokenStore(hazelcastInstance);
    }

    @Bean
    @ConditionalOnMissingBean
    JwtProvider sjaJwtProvider(JwtSettings jwtSettings) {
        return new JwtProvider(jwtSettings);
    }

    @Bean
    @ConditionalOnMissingBean
    TokenIssuer sjaTokenIssuer(JwtProvider jwtProvider,
                                  RefreshTokenStore refreshTokenStore,
                                  JwtSettings jwtSettings) {
        return new TokenIssuer(jwtProvider, refreshTokenStore, jwtSettings);
    }

    @Bean
    @ConditionalOnMissingBean
    CookieHelper sjaCookieHelper(WebSettings webSettings, AuthProperties properties) {
        return new CookieHelper(webSettings, properties.jwt().refreshTokenExpiry());
    }

    @Bean
    @ConditionalOnMissingBean
    AuthInterceptor sjaAuthInterceptor(JwtProvider jwtProvider,
                                        ObjectMapper objectMapper,
                                        SecuritySettings securitySettings) {
        return new AuthInterceptor(jwtProvider, objectMapper, securitySettings);
    }

    @Bean
    @ConditionalOnMissingBean
    AuthPolicyAuditor sjaAuthPolicyAuditor(RequestMappingHandlerMapping handlerMapping,
                                           AuthInterceptor authInterceptor,
                                           SecuritySettings securitySettings) {
        return new AuthPolicyAuditor(handlerMapping, authInterceptor, securitySettings);
    }

    @Bean
    @ConditionalOnMissingBean(name = "sjaWebMvcConfigurer")
    WebMvcConfigurer sjaWebMvcConfigurer(AuthInterceptor authInterceptor) {
        return new WebMvcConfig(authInterceptor);
    }

    // Session endpoints (refresh + logout) — always on if library enabled
    @Bean
    @ConditionalOnMissingBean(SessionApplicationService.class)
    SessionApplicationService sjaSessionService(RefreshTokenStore store, TokenIssuer tokenIssuer) {
        return new SessionApplicationService(store, tokenIssuer);
    }

    @Bean
    @ConditionalOnMissingBean
    SessionController sjaSessionController(RefreshUseCase refreshUseCase,
                                              LogoutUseCase logoutUseCase,
                                              CookieHelper cookieHelper) {
        return new SessionController(refreshUseCase, logoutUseCase, cookieHelper);
    }

    /** Local login path — active only when a PasswordVerifier is provided. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnBean(PasswordVerifier.class)
    static class LoginConfig {

        @Bean
        @ConditionalOnMissingBean(LoginApplicationService.class)
        LoginApplicationService sjaLoginService(PasswordVerifier verifier, TokenIssuer tokenIssuer) {
            return new LoginApplicationService(verifier, tokenIssuer);
        }

        @Bean
        @ConditionalOnMissingBean
        LoginController sjaLoginController(LoginUseCase loginUseCase, CookieHelper cookieHelper) {
            return new LoginController(loginUseCase, cookieHelper);
        }
    }

    /** OAuth path — active only when an OAuthUserResolver is provided. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnBean(OAuthUserResolver.class)
    static class OAuthConfig {

        @Bean
        @ConditionalOnMissingBean
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
        JwksProvider sjaGoogleJwksProvider(HazelcastInstance hazelcastInstance,
                                              @Qualifier("sjaOAuthRestClient") RestClient restClient,
                                              ObjectMapper objectMapper) {
            return new HazelcastCachedGoogleJwksProvider(hazelcastInstance, restClient, objectMapper);
        }

        @Bean
        @ConditionalOnMissingBean
        GoogleOAuthClient googleOAuthClient(OAuthGoogleSettings settings,
                                            @Qualifier("sjaOAuthRestClient") RestClient restClient,
                                            ObjectMapper objectMapper,
                                            JwksProvider jwksProvider) {
            return new GoogleOAuthClient(settings, restClient, objectMapper, jwksProvider);
        }

        @Bean
        @ConditionalOnMissingBean(name = "sjaOAuthClientMap")
        Map<OAuthProvider, OAuthClient> sjaOAuthClientMap(List<OAuthClient> clients) {
            Map<OAuthProvider, OAuthClient> result = new EnumMap<>(OAuthProvider.class);
            for (OAuthClient client : clients) {
                for (OAuthProvider provider : OAuthProvider.values()) {
                    if (client.supports(provider)) {
                        result.put(provider, client);
                    }
                }
            }
            return result;
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
        @ConditionalOnMissingBean(OAuthApplicationService.class)
        OAuthApplicationService sjaOAuthService(
                OAuthUserResolver resolver,
                @Qualifier("sjaOAuthClientMap") Map<OAuthProvider, OAuthClient> clients,
                OAuthStateStore stateStore,
                OAuthCodeStore codeStore,
                TokenIssuer tokenIssuer) {
            return new OAuthApplicationService(resolver, clients, stateStore, codeStore, tokenIssuer);
        }

        @Bean
        @ConditionalOnMissingBean
        OAuthController sjaOAuthController(OAuthLoginUseCase useCase,
                                              CookieHelper cookieHelper,
                                              WebSettings webSettings) {
            return new OAuthController(useCase, cookieHelper, webSettings);
        }
    }
}
