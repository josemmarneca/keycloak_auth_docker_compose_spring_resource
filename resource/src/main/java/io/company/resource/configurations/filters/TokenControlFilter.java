package io.company.resource.configurations.filters;

import io.micrometer.common.util.StringUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class TokenControlFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String AUTHORIZATION_BEARER = "Bearer";
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // We will provide our own validation logic from scratch
        // If you are using Spring OAuth or something similar
        // you can instead use the already authenticated token, something like:
        // Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
        //    Jwt jwt = (Jwt) authentication.getPrincipal();
        //    String sessionId = jwt.getClaimAsString("sessionid");
        //    ...

        // Resolve token from request
        String jwt = getTokenFromRequest(request);
        if (jwt == null) {
            // your choice... mine
            filterChain.doFilter(request, response);
            return;
        }

        // If the token is not valid, raise error
        if (!this.validateToken(jwt)) {
            throw new BadCredentialsException("Session expired");
        }

        // Continue filter chain
        filterChain.doFilter(request, response);
    }

    // Resolve token from Authorization header
    private String getTokenFromRequest(HttpServletRequest request){
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.isNotEmpty(bearerToken) && bearerToken.startsWith(AUTHORIZATION_BEARER)) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }

    // Validate the JWT token
    // We can use the jjwt library, for instance, to process the JWT token claims
    private boolean validateToken(String token) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null) {
                if (authentication.getPrincipal() instanceof KeycloakPrincipal) {
                    KeycloakPrincipal<KeycloakSecurityContext> kp = (KeycloakPrincipal<KeycloakSecurityContext>) authentication.getPrincipal();
                    // retrieving username here
                    String username = kp.getKeycloakSecurityContext().getToken().getPreferredUsername();
                }
            }

            return true;
        } catch (Exception e) {
            // consider logging the error. Handle as appropriate
        }

        return false;
    }
}
