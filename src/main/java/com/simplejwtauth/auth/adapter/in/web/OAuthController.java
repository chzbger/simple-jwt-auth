package com.simplejwtauth.auth.adapter.in.web;

import com.simplejwtauth.auth.adapter.in.web.dto.OAuthExchangeRequest;
import com.simplejwtauth.auth.adapter.in.web.dto.TokenResponse;
import com.simplejwtauth.auth.application.config.WebSettings;
import com.simplejwtauth.auth.application.port.in.OAuthLoginUseCase;
import com.simplejwtauth.auth.application.port.in.OAuthLoginUseCase.OAuthCallbackResult;
import com.simplejwtauth.auth.adapter.in.web.annotation.Auth;
import com.simplejwtauth.auth.domain.OAuthProvider;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Auth(isAuth = false)
@RestController
@RequiredArgsConstructor
@RequestMapping("${simple-jwt-auth.web.base-path:/api/auth}/oauth")
public class OAuthController {

    private final OAuthLoginUseCase oAuthLoginUseCase;
    private final CookieHelper cookieHelper;
    private final WebSettings web;

    @GetMapping("/google")
    public void redirectToGoogle(HttpServletResponse response) throws IOException {
        String url = oAuthLoginUseCase.getAuthorizationUrl(OAuthProvider.GOOGLE);
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.sendRedirect(url);
    }

    @GetMapping("/google/callback")
    public void googleCallback(@RequestParam(value = "code", required = false) String code,
                               @RequestParam(value = "state", required = false) String state,
                               @RequestParam(value = "error", required = false) String error,
                               HttpServletResponse response) throws IOException {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader("Referrer-Policy", "no-referrer");

        if (error != null) {
            response.sendRedirect(web.postLoginErrorRedirect() + urlEncode(error));
            return;
        }
        if (code == null || state == null) {
            response.sendRedirect(web.postLoginErrorRedirect() + "missing_params");
            return;
        }

        try {
            OAuthCallbackResult result = oAuthLoginUseCase.handleCallback(
                    OAuthProvider.GOOGLE, code, state);
            cookieHelper.setRefreshCookie(response, result.refreshToken());
            response.sendRedirect(buildRedirectUrl(web.postLoginRedirect(), result.oneTimeCode()));
        } catch (IllegalArgumentException ex) {
            response.sendRedirect(web.postLoginErrorRedirect() + "invalid_state");
        } catch (RuntimeException ex) {
            response.sendRedirect(web.postLoginErrorRedirect() + "oauth_failed");
        }
    }

    @PostMapping("/exchange")
    public ResponseEntity<TokenResponse> exchange(@RequestBody OAuthExchangeRequest request) {
        try {
            String accessToken = oAuthLoginUseCase.consumeOneTimeCode(request.code());
            return ResponseEntity.ok()
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .body(new TokenResponse(accessToken));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.status(401)
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .build();
        }
    }

    private static String buildRedirectUrl(String base, String oneTimeCode) {
        // Split off the fragment (if any) so `sja_code` lands in the query string,
        // not inside `#...` — otherwise hash-routing SPAs can't see it.
        int hashIdx = base.indexOf('#');
        String path = hashIdx < 0 ? base : base.substring(0, hashIdx);
        String fragment = hashIdx < 0 ? "" : base.substring(hashIdx);
        String sep = path.contains("?") ? "&" : "?";
        return path + sep + "sja_code=" + urlEncode(oneTimeCode) + fragment;
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
