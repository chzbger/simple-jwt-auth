package com.simplejwtauth.adapter.in.web;

import com.simplejwtauth.adapter.in.web.dto.LoginRequest;
import com.simplejwtauth.adapter.in.web.dto.TokenResponse;
import com.simplejwtauth.application.port.in.LoginUseCase;
import com.simplejwtauth.config.Auth;
import com.simplejwtauth.domain.model.AuthToken;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Auth(isAuth = false)
@RestController
@RequestMapping("${simple-jwt-auth.web.base-path:/api/auth}")
public class LoginController {

    private final LoginUseCase loginUseCase;
    private final CookieHelper cookieHelper;

    public LoginController(LoginUseCase loginUseCase, CookieHelper cookieHelper) {
        this.loginUseCase = loginUseCase;
        this.cookieHelper = cookieHelper;
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest request,
                                               HttpServletResponse response) {
        AuthToken token = loginUseCase.login(request.username(), request.password());
        cookieHelper.setRefreshCookie(response, token.refreshToken());
        return ResponseEntity.ok(new TokenResponse(token.accessToken()));
    }
}
