package com.simplejwtauth.common.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.simplejwtauth.auth.adapter.in.web.CookieHelper;
import com.simplejwtauth.auth.application.config.WebSettings;
import com.simplejwtauth.auth.application.port.in.LogoutUseCase;
import com.simplejwtauth.auth.application.service.TokenIssuer;
import jakarta.servlet.http.HttpServletResponse;
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
            Optional<ClientRegistrationRepository> clientRegistrations,
            Optional<OAuth2LoginSuccessHandler> oauth2SuccessHandler,
            Optional<OAuth2LoginFailureHandler> oauth2FailureHandler,
            Optional<AuthorizationRequestRepository<OAuth2AuthorizationRequest>> authorizationRequestRepository
    ) throws Exception {
        String base = web.basePath();

        JsonAuthenticationFilter loginFilter = new JsonAuthenticationFilter(base + "/login", objectMapper);
        loginFilter.setAuthenticationManager(authenticationManager);
        loginFilter.setAuthenticationSuccessHandler(new LocalLoginSuccessHandler(tokenIssuer, cookieHelper, objectMapper));
        loginFilter.setAuthenticationFailureHandler(new LocalLoginFailureHandler(objectMapper));


        RefreshTokenLogoutHandler logoutHandler = new RefreshTokenLogoutHandler(logoutUseCase, cookieHelper, web);
        JsonAuthenticationEntryPoint authenticationEntryPoint = new JsonAuthenticationEntryPoint(objectMapper);
        JsonAccessDeniedHandler accessDeniedHandler = new JsonAccessDeniedHandler(objectMapper);

        http
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authz -> authz
                        // 라이브러리 endpoint — bearer 없이 접근 가능
                        .requestMatchers(HttpMethod.POST,
                                base + "/login",
                                base + "/refresh",
                                base + "/logout",
                                base + "/oauth/exchange").permitAll()
                        .requestMatchers(base + "/oauth/**").permitAll()
                        .requestMatchers("/sja/**").permitAll()
                        // 그 외 — 인증 결정은 메서드 보안 (@Auth) 에 위임
                        .anyRequest().permitAll()
                )
                .exceptionHandling(eh -> eh
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )
                .oauth2ResourceServer(rs -> rs
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )
                .logout(logout -> logout
                        .logoutUrl(base + "/logout")
                        .addLogoutHandler(logoutHandler)
                        .logoutSuccessHandler((req, res, auth) -> {
                            res.setStatus(HttpServletResponse.SC_OK);
                            res.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
                        })
                )
                .addFilterBefore(loginFilter, UsernamePasswordAuthenticationFilter.class);

        // OAuth2 / OIDC 로그인 — yml 에 client registration 이 있고 OAuthUserResolver 도 등록된 경우만
        if (clientRegistrations.isPresent() && oauth2SuccessHandler.isPresent()) {
            http.oauth2Login(oauth2 -> {
                oauth2
                        .authorizationEndpoint(ep -> {
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
    JwtAuthenticationConverter sjaJwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setPrincipalClaimName("sub");
        // 우리 access token 에 권한/role claim 없음 — 향후 필요 시 매핑 추가
        converter.setJwtGrantedAuthoritiesConverter(jwt -> Collections.emptyList());
        return converter;
    }

    @Bean
    @ConditionalOnMissingBean(AuthenticationManager.class)
    AuthenticationManager sjaAuthenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    /** 기본 PasswordEncoder. 다른 알고리즘 원하면 소비자가 빈으로 override. */
    @Bean
    @ConditionalOnMissingBean(PasswordEncoder.class)
    PasswordEncoder sjaPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
