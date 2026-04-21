package com.simplejwtauth.auth.adapter.in.web.local;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.simplejwtauth.auth.adapter.in.web.CookieHelper;
import com.simplejwtauth.auth.adapter.in.web.dto.TokenResponse;
import com.simplejwtauth.auth.application.service.TokenIssuer;
import com.simplejwtauth.auth.domain.AuthToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

/**
 * 로그인 성공, 토큰 발급
 */
@RequiredArgsConstructor
public class LocalLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final TokenIssuer tokenIssuer;
    private final CookieHelper cookieHelper;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        Object principal = authentication.getPrincipal();
        String userId = principal instanceof UserDetails ud
                ? ud.getUsername()
                : authentication.getName();

        AuthToken tokens = tokenIssuer.issueTokens(userId);
        cookieHelper.setRefreshCookie(response, tokens.refreshToken());

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        objectMapper.writeValue(response.getWriter(), new TokenResponse(tokens.accessToken()));
    }
}
