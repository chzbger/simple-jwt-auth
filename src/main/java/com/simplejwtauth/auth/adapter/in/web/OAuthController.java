package com.simplejwtauth.auth.adapter.in.web;

import com.simplejwtauth.auth.adapter.in.web.dto.OAuthExchangeRequest;
import com.simplejwtauth.auth.adapter.in.web.dto.TokenResponse;
import com.simplejwtauth.auth.application.port.in.OAuthExchangeUseCase;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * OAuth2LoginSuccessHandler 가 발급한 1회용 code (sja_code) 를 access token 으로 교환.
 * callback은 spring security OAuth2LoginSuccessHandler
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("${simple-jwt-auth.web.base-path:/api/auth}/oauth")
public class OAuthController {

    private final OAuthExchangeUseCase exchangeUseCase;

    @PostMapping("/exchange")
    public ResponseEntity<TokenResponse> exchange(@RequestBody OAuthExchangeRequest request) {
        String token = exchangeUseCase.exchange(request.code());
        if (token == null) {
            return ResponseEntity.status(401)
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .build();
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(new TokenResponse(token));
    }
}
