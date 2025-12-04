package com.musicfly.backend.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.musicfly.backend.models.UserOptionsUUID;
import com.musicfly.backend.properties.ApplicationProperties;
import com.musicfly.backend.repositories.UserRepository;
import com.musicfly.backend.services.JwtService;
import com.musicfly.backend.services.RedisTokenService;
import com.musicfly.backend.views.DTO.ErrorResponseDTO;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final JwtService jwtService;
    private final JwtDecoder jwtDecoder;
    private final UserDetailsService userDetailsService;
    private final RedisTokenService redisTokenService;
    private final UserRepository userRepository;
    private final ApplicationProperties applicationProperties;

    private final static String APPLICATION_TYPE = "application/json";

    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String token = getTokenFromRequest(request);
        final String username;
        final String ip = request.getRemoteAddr();

        String path = request.getServletPath();
        if (path.startsWith("/swagger-ui") || path.startsWith("/v3/api-docs") || path.startsWith("/eureka") || path.equals("/")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Si la opción "Open Doors" está habilitada, no procesamos la autenticación JWT
        if (applicationProperties != null && applicationProperties.isOpenDoors()) {
            filterChain.doFilter(request, response);
            return;
        }

        // Si no hay token en header ni cookies, continuamos la cadena sin autenticar
        if (token == null) {
            logger.debug("CONTROLLER REQUEST WITHOUT TOKEN - IP: {} - URI: {}", ip, request.getRequestURI());
            filterChain.doFilter(request, response);
            return;
        }

        // Validar formato JWT
        try {
            jwtDecoder.decode(token);
        } catch (Exception e) {
            e.printStackTrace();
            logger.warn("Invalid JWT token provided - IP: {} - URI: {} - Error: {}", ip, request.getRequestURI(), e.getMessage());
            response.setContentType(APPLICATION_TYPE);
            response.setCharacterEncoding("UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write(MAPPER.writeValueAsString(ErrorResponseDTO.builder()
                    .error("token_is_invalid")
                    .message("This token is invalid.")
                    .statusCode(HttpStatus.UNAUTHORIZED.value())
                    .timestamp(LocalDateTime.now().toString())
                    .build()));
            return;
        }

        username = jwtService.getUsernameFromToken(token);

        // Comprueba si el token está en la blacklist
        if (redisTokenService.hasTokenType(UserOptionsUUID.BLACK_LIST, token)) {
            logger.warn("CONTROLLER REQUEST WITH BLACKLISTED TOKEN - IP: {} - URI: {} - TOKEN: {}", ip, request.getRequestURI(), token);
            response.setContentType(APPLICATION_TYPE);
            response.setCharacterEncoding("UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write(MAPPER.writeValueAsString(ErrorResponseDTO.builder()
                    .error("token_is_blacklist")
                    .message("This token is blacklisted.")
                    .statusCode(HttpStatus.UNAUTHORIZED.value())
                    .timestamp(LocalDateTime.now().toString())
                    .build()));
            SecurityContextHolder.clearContext();
            return;
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (jwtService.isTokenValid(token, userDetails, request)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                logger.info("CONTROLLER REQUEST WITH TOKEN SUCCESS - IP: {} - URI: {} - TOKEN: {}", ip, request.getRequestURI(), token);
                SecurityContextHolder.getContext().setAuthentication(authToken);
                filterChain.doFilter(request, response);
                return;
            } else {
                logger.warn("CONTROLLER REQUEST WITH TOKEN FAILED - IP: {} - URI: {} - TOKEN: {}", ip, request.getRequestURI(), token);
                response.setContentType(APPLICATION_TYPE);
                response.setCharacterEncoding("UTF-8");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write(MAPPER.writeValueAsString(ErrorResponseDTO.builder()
                        .error("token_invalid")
                        .message("This token is not valid.")
                        .statusCode(HttpStatus.UNAUTHORIZED.value())
                        .timestamp(LocalDateTime.now().toString())
                        .build()));
                SecurityContextHolder.clearContext();
                return;
            }
        }

        // Si llegamos aquí no había username o ya estaba autenticado: continuamos la cadena
        filterChain.doFilter(request, response);
    }

    public String getTokenFromRequest(HttpServletRequest request) {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        } else if (request.getCookies() != null) {
            return extractTokenFromCookies(request);
        }

        return null;
    }

    public String extractTokenFromCookies(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
