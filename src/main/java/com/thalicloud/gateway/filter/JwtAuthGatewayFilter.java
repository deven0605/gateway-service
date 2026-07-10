package com.thalicloud.gateway.filter;

import com.thalicloud.gateway.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

/**
 * Global JWT pre-validation filter.
 *
 * Runs before every route and rejects unauthenticated requests to protected
 * paths with 401 before they reach any downstream service.
 *
 * Public paths (no token required):
 *   POST /api/auth/login
 *   POST /api/auth/register
 *   POST /api/auth/refresh
 *   POST /api/auth/logout
 *   GET  /api/kitchens, /api/kitchens/**, /api/search  (public kitchen discovery, SRS M3)
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthGatewayFilter implements GlobalFilter, Ordered {

    private final JwtService jwtService;

    // All /api/auth/** requests are forwarded as-is — auth-service handles its own security.
    private static final String AUTH_PATH_PREFIX = "/api/auth/";

    // Public kitchen discovery endpoints — vendor-service permits these with no auth too.
    private static final String KITCHENS_PATH = "/api/kitchens";
    private static final String KITCHENS_PATH_PREFIX = "/api/kitchens/";
    private static final String SEARCH_PATH = "/api/search";

    // Health check / internal paths that bypass JWT validation.
    private static final Set<String> OPEN_PATHS = Set.of("/actuator/health");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path   = request.getURI().getPath();
        String method = request.getMethod().name();

        // Pass OPTIONS preflight through — CORS headers are added by globalcors config.
        if ("OPTIONS".equalsIgnoreCase(method)) {
            return chain.filter(exchange);
        }

        // Auth, health, and public kitchen-discovery paths need no gateway-level token check.
        if (path.startsWith(AUTH_PATH_PREFIX) || OPEN_PATHS.contains(path)
                || path.equals(KITCHENS_PATH) || path.startsWith(KITCHENS_PATH_PREFIX)
                || path.equals(SEARCH_PATH)) {
            return chain.filter(exchange);
        }

        // All other paths require a valid Bearer token.
        List<String> authHeaders = request.getHeaders().get(HttpHeaders.AUTHORIZATION);
        if (authHeaders == null || authHeaders.isEmpty()) {
            log.warn("GATEWAY 401 — missing Authorization header: {} {}", method, path);
            return writeError(exchange, "MISSING_TOKEN", "Authorization header is required");
        }

        String bearer = authHeaders.get(0);
        if (!bearer.startsWith("Bearer ")) {
            log.warn("GATEWAY 401 — malformed Authorization header: {} {}", method, path);
            return writeError(exchange, "INVALID_TOKEN", "Bearer token is required");
        }

        String token = bearer.substring(7);
        if (!jwtService.isTokenValid(token)) {
            log.warn("GATEWAY 401 — invalid or expired token: {} {}", method, path);
            return writeError(exchange, "TOKEN_EXPIRED", "Access token is invalid or has expired");
        }

        log.debug("GATEWAY — token valid, forwarding: {} {}", method, path);
        return chain.filter(exchange);
    }

    /**
     * Writes a JSON error response matching the spec error envelope:
     * {"error":{"code":"...","message":"..."}}
     */
    private Mono<Void> writeError(ServerWebExchange exchange, String code, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String body = String.format(
            "{\"error\":{\"code\":\"%s\",\"message\":\"%s\"}}",
            code, message
        );
        DataBuffer buffer = response.bufferFactory()
                .wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    /** Run before the RoutePredicateHandlerMapping (-1). */
    @Override
    public int getOrder() {
        return -100;
    }
}
