package com.simplejwtauth.auth.adapter.in.web.oauth;

import com.simplejwtauth.auth.application.config.WebSettings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * OAuth 로그인 실패 redirect.
 */
@RequiredArgsConstructor
public class OAuth2LoginFailureHandler implements AuthenticationFailureHandler {

    private final WebSettings webSettings;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        String errorCode = "oauth_failed";
        if (exception instanceof OAuth2AuthenticationException oae) {
            errorCode = oae.getError().getErrorCode();
        }
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.sendRedirect(webSettings.postLoginErrorRedirect() + URLEncoder.encode(errorCode, StandardCharsets.UTF_8));
    }
}
