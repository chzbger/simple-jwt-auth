package com.simplejwtauth.auth.adapter.out.hazelcast;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.map.IMap;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * stateless 하게 OAuth2 authorization request 보관
 * Spring Security 기본 HttpSessionOAuth2AuthorizationRequestRepository 가 session 만드는걸 회피
 * key 는 Spring Security 가 생성한 OAuth state 토큰
 */
public class HazelcastAuthorizationRequestRepository
        implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    static final String MAP_NAME = "simple-jwt-auth:oauth-authz-request";
    private static final String STATE_PARAM = "state";

    private final IMap<String, OAuth2AuthorizationRequest> store;

    public HazelcastAuthorizationRequestRepository(HazelcastInstance hazelcastInstance) {
        this.store = hazelcastInstance.getMap(MAP_NAME);
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        String state = request.getParameter(STATE_PARAM);
        if (state == null || state.isBlank()) return null;
        return store.get(state);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest,
                                         HttpServletRequest request,
                                         HttpServletResponse response) {
        if (authorizationRequest == null) {
            removeAuthorizationRequest(request, response);
            return;
        }
        String state = authorizationRequest.getState();
        if (state == null || state.isBlank()) {
            throw new IllegalArgumentException("OAuth2AuthorizationRequest 에 state 토큰이 없습니다");
        }
        store.set(state, authorizationRequest);
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        String state = request.getParameter(STATE_PARAM);
        if (state == null || state.isBlank()) return null;
        return store.remove(state);
    }
}
