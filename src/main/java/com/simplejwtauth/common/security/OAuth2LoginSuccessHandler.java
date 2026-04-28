package com.simplejwtauth.common.security;

import com.simplejwtauth.auth.adapter.in.web.CookieHelper;
import com.simplejwtauth.auth.application.config.WebSettings;
import com.simplejwtauth.auth.application.port.out.OAuthCodeStore;
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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * OAuth2/OIDC 로그인 성공 → OAuthUserResolver 로 userId 매핑 → 토큰 발급 → sja_code 로 redirect
 * access token 을 URL 에 직접 안 넣는 이유: history/Referer/access 로그 유출 방지
 */
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final OAuthUserResolver userResolver;
    private final TokenIssuer tokenIssuer;
    private final CookieHelper cookieHelper;
    private final OAuthCodeStore codeStore;
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
        String oneTimeCode = codeStore.issue(tokens.accessToken());

        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader("Referrer-Policy", "no-referrer");
        response.sendRedirect(buildRedirectUrl(webSettings.postLoginRedirect(), oneTimeCode));
    }

    private static String extractProviderId(OAuth2User principal) {
        if (principal instanceof OidcUser oidc) {
            return oidc.getSubject();
        }
        // OIDC 가 아닌 plain OAuth2 — provider 마다 안정 식별자 위치가 다름.
        // Spring Security 가 registration 의 user-name-attribute 를 resolve 한 결과.
        return principal.getName();
    }

    private static String buildRedirectUrl(String base, String oneTimeCode) {
        // URL fragment 가 있으면 분리해서 sja_code 가 fragment 내부가 아니라 query string 에 가도록.
        // (hash-routing SPA 가 fragment 안의 param 을 못 보는 케이스 방지)
        int hashIdx = base.indexOf('#');
        String path = hashIdx < 0 ? base : base.substring(0, hashIdx);
        String fragment = hashIdx < 0 ? "" : base.substring(hashIdx);
        String sep = path.contains("?") ? "&" : "?";
        return path + sep + "sja_code=" + URLEncoder.encode(oneTimeCode, StandardCharsets.UTF_8) + fragment;
    }
}
