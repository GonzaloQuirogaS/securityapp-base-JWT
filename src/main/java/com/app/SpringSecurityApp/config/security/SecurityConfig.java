package com.app.SpringSecurityApp.config.security;

import com.app.SpringSecurityApp.config.filter.JwtTokenValidator;
import com.app.SpringSecurityApp.service.UserDetailServiceImpl;
import com.app.SpringSecurityApp.util.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtUtils jwtUtils;

    public SecurityConfig(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity

                //Cross-site request forgery, vulnerabilidad web en apps con formularios y manejo de sesiones.
                .csrf(csrf -> csrf.disable())

                //Se utiliza para cuando se loguea con usuario y contraseña y no TOKEN
                .httpBasic(Customizer.withDefaults())

                //Manejo de sesion, STATELESS para que no expire la sesion ni se guarde en memoria
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                //Autorizar endpoints y peticiones
                .authorizeHttpRequests(http -> {

                    //Publicos
                    http.requestMatchers(HttpMethod.POST, "/auth/**").permitAll();

                    //Privados
                    http.requestMatchers(HttpMethod.POST, "/method/post").hasAnyRole("ADMIN","DEVELOPER");
                    http.requestMatchers(HttpMethod.PATCH, "/method/patch").hasAnyAuthority("REFACTOR");

                    //Denegar acceso a cualquier endpoint no especificado
                    http.anyRequest().denyAll();

                    //Denegar acceso a cualquier endpoint no especificado si no se esta autenticado antes
                    //http.anyRequest().authenticated();
                })

                //Validamos el token antes de BasicAuthenticationFilter
                .addFilterBefore( new JwtTokenValidator(jwtUtils), BasicAuthenticationFilter.class)
                .build();
    }

    //Administra la autenticacion
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    //Proveedor de autenticacion
    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailServiceImpl userDetailService) {

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        //UserDetailService, trae usuario de BD
        provider.setUserDetailsService(userDetailService);
        return provider;
    }

    //Password Encoder encripta contraseñas
    @Bean
    public PasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();

        //Solo para pruebas
        // return NoOpPasswordEncoder.getInstance();
    }



}
