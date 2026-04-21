package com.simplejwtauth.auth.adapter.out.hazelcast;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.map.IMap;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;

/**
 * OAuth2 authorizationRequest 보관
 */
public class HazelcastAuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    public static final String MAP_NAME = "simple-jwt-auth:oauth-authz-request";

    private final IMap<String, OAuth2AuthorizationRequest> stateToRequest;

    public HazelcastAuthorizationRequestRepository(HazelcastInstance hazelcastInstance) {
        this.stateToRequest = hazelcastInstance.getMap(MAP_NAME);
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
        Assert.hasText(state, "authorizationRequest.state cannot be empty");
        stateToRequest.set(state, authorizationRequest);
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        Assert.notNull(request, "request cannot be null");
        String state = request.getParameter(OAuth2ParameterNames.STATE);
        if (state == null || state.isBlank()) return null;
        return stateToRequest.get(state);
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        Assert.notNull(request, "request cannot be null");
        String state = request.getParameter(OAuth2ParameterNames.STATE);
        if (state == null || state.isBlank()) return null;
        return stateToRequest.remove(state);
    }
}
