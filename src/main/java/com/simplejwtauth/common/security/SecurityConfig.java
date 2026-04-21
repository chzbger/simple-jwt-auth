package com.simplejwtauth.common.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hazelcast.core.HazelcastInstance;
import com.simplejwtauth.auth.adapter.in.web.CookieHelper;
import com.simplejwtauth.auth.adapter.in.web.RefreshTokenLogoutHandler;
import com.simplejwtauth.auth.adapter.in.web.local.JsonAuthenticationFilter;
import com.simplejwtauth.auth.adapter.in.web.local.LocalLoginFailureHandler;
import com.simplejwtauth.auth.adapter.in.web.local.LocalLoginSuccessHandler;
import com.simplejwtauth.auth.adapter.in.web.oauth.OAuth2LoginFailureHandler;
import com.simplejwtauth.auth.adapter.in.web.oauth.OAuth2LoginSuccessHandler;
import com.simplejwtauth.auth.adapter.out.hazelcast.HazelcastAuthorizationRequestRepository;
import com.simplejwtauth.auth.application.config.WebSettings;
import com.simplejwtauth.auth.application.port.in.LogoutUseCase;
import com.simplejwtauth.auth.application.port.out.OAuthUserResolver;
import com.simplejwtauth.auth.application.service.TokenIssuer;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collections;
import java.util.Optional;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    SecurityFilterChain sjaSecurityFilterChain(
            HttpSecurity http,
            WebSettings web,
            JwtAuthenticationConverter jwtAuthenticationConverter,
            AuthenticationManager authenticationManager,
            ObjectMapper objectMapper,
            TokenIssuer tokenIssuer,
            CookieHelper cookieHelper,
            LogoutUseCase logoutUseCase,
            JsonAuthenticationEntryPoint unauthorized,
            JsonAccessDeniedHandler forbidden,
            Optional<OAuth2LoginSuccessHandler> oauth2SuccessHandler,
            Optional<OAuth2LoginFailureHandler> oauth2FailureHandler,
            Optional<AuthorizationRequestRepository<OAuth2AuthorizationRequest>> authorizationRequestRepository
    ) throws Exception {
        String base = web.basePath();

        JsonAuthenticationFilter loginFilter = new JsonAuthenticationFilter(base + "/login", objectMapper);
        loginFilter.setAuthenticationManager(authenticationManager);
        loginFilter.setAuthenticationSuccessHandler(new LocalLoginSuccessHandler(tokenIssuer, cookieHelper, objectMapper));
        loginFilter.setAuthenticationFailureHandler(new LocalLoginFailureHandler(objectMapper));

        http
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(HttpMethod.POST,
                                base + "/login",
                                base + "/refresh",
                                base + "/logout").permitAll()
                        .requestMatchers(HttpMethod.GET, base + "/me").permitAll()
                        .requestMatchers(base + "/oauth/**").permitAll()
                        .requestMatchers("/sja/**").permitAll()
                        .anyRequest().permitAll()
                )
                .exceptionHandling(eh -> eh
                        .authenticationEntryPoint(unauthorized)
                        .accessDeniedHandler(forbidden)
                )
                .oauth2ResourceServer(rs -> rs
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
                        .authenticationEntryPoint(unauthorized)
                        .accessDeniedHandler(forbidden)
                )
                .logout(logout -> logout
                        .logoutUrl(base + "/logout")
                        .addLogoutHandler(new RefreshTokenLogoutHandler(logoutUseCase, cookieHelper, web))
                        .logoutSuccessHandler((req, res, auth) -> {
                            res.setStatus(HttpServletResponse.SC_OK);
                            res.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
                        })
                )
                .addFilterBefore(loginFilter, UsernamePasswordAuthenticationFilter.class);

        // OAuth 로그인(OAuthUserResolver 등록된 경우만)
        if (oauth2SuccessHandler.isPresent()) {
            http.oauth2Login(oauth2 -> {
                oauth2.authorizationEndpoint(ep -> {
                    ep.baseUri(base + "/oauth");
                        authorizationRequestRepository.ifPresent(ep::authorizationRequestRepository);
                    })
                    .redirectionEndpoint(ep -> ep.baseUri(base + "/oauth/callback/*"))
                    .successHandler(oauth2SuccessHandler.get());
                oauth2FailureHandler.ifPresent(oauth2::failureHandler);
            });
        }

        return http.build();
    }

    @Bean
    @ConditionalOnMissingBean
    JsonAuthenticationEntryPoint sjaAuthenticationEntryPoint(ObjectMapper objectMapper) {
        return new JsonAuthenticationEntryPoint(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    JsonAccessDeniedHandler sjaAccessDeniedHandler(ObjectMapper objectMapper) {
        return new JsonAccessDeniedHandler(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    JwtAuthenticationConverter sjaJwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setPrincipalClaimName("sub");
        converter.setJwtGrantedAuthoritiesConverter(jwt -> Collections.emptyList());
        return converter;
    }

    @Bean
    @ConditionalOnMissingBean(AuthenticationManager.class)
    AuthenticationManager sjaAuthenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    @ConditionalOnMissingBean(PasswordEncoder.class)
    PasswordEncoder sjaPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @ConditionalOnBean(OAuthUserResolver.class)
    AuthorizationRequestRepository<OAuth2AuthorizationRequest> sjaAuthorizationRequestRepository(HazelcastInstance hazelcastInstance) {
        return new HazelcastAuthorizationRequestRepository(hazelcastInstance);
    }

    @Bean
    @ConditionalOnBean(OAuthUserResolver.class)
    OAuth2LoginSuccessHandler sjaOAuth2LoginSuccessHandler(OAuthUserResolver resolver,
                                                          TokenIssuer tokenIssuer,
                                                          CookieHelper cookieHelper,
                                                          WebSettings webSettings) {
        return new OAuth2LoginSuccessHandler(resolver, tokenIssuer, cookieHelper, webSettings);
    }

    @Bean
    @ConditionalOnBean(OAuthUserResolver.class)
    OAuth2LoginFailureHandler sjaOAuth2LoginFailureHandler(WebSettings webSettings) {
        return new OAuth2LoginFailureHandler(webSettings);
    }
}
