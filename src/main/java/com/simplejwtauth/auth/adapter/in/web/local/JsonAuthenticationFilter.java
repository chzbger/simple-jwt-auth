package com.simplejwtauth.auth.adapter.in.web.local;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.simplejwtauth.auth.adapter.in.web.local.dto.LoginRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

/**
 * 로그인 필터(json)
 * 실제 로그인은 UserDetailsService을 구현해서 처리
 */
public class JsonAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final ObjectMapper objectMapper;

    public JsonAuthenticationFilter(String loginUrl, ObjectMapper objectMapper) {
        super(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, loginUrl));
        this.objectMapper = objectMapper;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        LoginRequest body;
        try {
            body = objectMapper.readValue(request.getInputStream(), LoginRequest.class);
        } catch (Exception ex) {
            throw new AuthenticationServiceException("Invalid format", ex);
        }

        if (body == null
                || body.userId() == null || body.userId().isBlank()
                || body.password() == null || body.password().isBlank()) {
            throw new AuthenticationServiceException("Invalid field");
        }

        UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated(body.userId(), body.password());
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
        return getAuthenticationManager().authenticate(authRequest);
    }
}
