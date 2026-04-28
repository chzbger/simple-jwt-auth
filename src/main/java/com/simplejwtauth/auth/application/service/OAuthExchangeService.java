package com.simplejwtauth.auth.application.service;

import com.simplejwtauth.auth.application.port.in.OAuthExchangeUseCase;
import com.simplejwtauth.auth.application.port.out.OAuthCodeStore;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class OAuthExchangeService implements OAuthExchangeUseCase {

    private final OAuthCodeStore codeStore;

    @Override
    public String exchange(String code) {
        return codeStore.consume(code);
    }
}
