package com.simplejwtauth.auth.adapter.in.web.oauth;

import com.simplejwtauth.auth.adapter.in.web.CookieHelper;
import com.simplejwtauth.auth.application.config.WebSettings;
import com.simplejwtauth.auth.application.port.out.OAuthUserResolver;
import com.simplejwtauth.auth.application.service.TokenIssuer;
import com.simplejwtauth.auth.domain.AuthToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

/**
 * OAuth 로그인 성공
 */
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final OAuthUserResolver userResolver;
    private final TokenIssuer tokenIssuer;
    private final CookieHelper cookieHelper;
    private final WebSettings webSettings;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        String registrationId = token.getAuthorizedClientRegistrationId();
        String providerId = extractProviderId(token.getPrincipal());

        String userId = userResolver.resolve(registrationId, providerId);
        AuthToken tokens = tokenIssuer.issueTokens(userId);
        cookieHelper.setRefreshCookie(response, tokens.refreshToken());

        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader("Referrer-Policy", "no-referrer");
        response.sendRedirect(webSettings.postLoginRedirect());
    }

    private static String extractProviderId(OAuth2User principal) {
        if (principal instanceof OidcUser oidc) {
            return oidc.getSubject();
        }
        return principal.getName();
    }
}
