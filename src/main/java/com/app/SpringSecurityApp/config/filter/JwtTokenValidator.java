package com.app.SpringSecurityApp.config.filter;

import com.app.SpringSecurityApp.util.JwtUtils;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;

//Filtro para validar token
public class JwtTokenValidator extends OncePerRequestFilter {

    private JwtUtils jwtUtils;

    public JwtTokenValidator(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        //Obtenemos el token
        String jwtToken = request.getHeader(HttpHeaders.AUTHORIZATION);

        //Validamos token
        if (jwtToken != null) {

            //Quitamos "Bearer" del token
            jwtToken = jwtToken.substring(7);

            //Validamos el token
            DecodedJWT decodedJWT = jwtUtils.validateToken(jwtToken);

            //Extraemos username
            String username = jwtUtils.extractUsername(decodedJWT);

            //Extraemos claim de authorities
            String stringAuthorities = jwtUtils.getSpecificClaim(decodedJWT, "authorities").asString();

            //Extraemos lista de authorities
            Collection<? extends GrantedAuthority> authorities = AuthorityUtils
                    .commaSeparatedStringToAuthorityList(stringAuthorities);


            //Autenticamos y asingamos el security context
            SecurityContext context = SecurityContextHolder.getContext();
            Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);

            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
        }

        filterChain.doFilter(request, response);
    }

}
