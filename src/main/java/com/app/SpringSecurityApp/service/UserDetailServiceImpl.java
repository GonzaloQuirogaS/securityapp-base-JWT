package com.app.SpringSecurityApp.service;

import com.app.SpringSecurityApp.controller.dto.AuthLoginRequest;
import com.app.SpringSecurityApp.controller.dto.AuthResponse;
import com.app.SpringSecurityApp.persistence.entity.UserEntity;
import com.app.SpringSecurityApp.repository.UserRepository;
import com.app.SpringSecurityApp.util.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity userEntity = userRepository.findUserEntityByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("El usuario " + username + " no existe."));


        //Lista de autoridades que recibe security
        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();

        //Tomamos roles de usuario y los convertimos a SimpleGrantedAuthority
        userEntity.getRoles()
                .forEach(role -> authorityList.add(new SimpleGrantedAuthority("ROLE_".concat(role.getRoleEnum().name()))));

        //Tomamos permisos de usuario y los convertimos a SimpleGrantedAuthority
        userEntity.getRoles().stream()
                .flatMap(role -> role.getPermissionList().stream())
                .forEach(permission -> authorityList.add(new SimpleGrantedAuthority(permission.getName())));

        return new User(userEntity.getUsername(),
                userEntity.getPassword(),
                userEntity.isEnabled(),
                userEntity.isAccountNoExpired(),
                userEntity.isCredentialNoExpired(),
                userEntity.isAccountNoLocked(),
                authorityList);
    }

    //Metodo login para user
    public AuthResponse loginUser(AuthLoginRequest authLoginRequest) {

        //Obtenemos los datos del login
        String username = authLoginRequest.username();
        String password = authLoginRequest.password();


        //Autenticamos si existe usuario con ese password
        Authentication authentication = this.authenticate(username, password);
        //Pasamos usuario al context holder
        SecurityContextHolder.getContext().setAuthentication(authentication);

        //Creamos token
        String accesToken = jwtUtils.createToken(authentication);

        AuthResponse authResponse = new AuthResponse(username, "User logged succesfully", accesToken, true);

        return authResponse;
    }

    //Metodo para autenticar usuario
    public Authentication authenticate(String username, String password) {

        //Buscamos usuario en BD
        UserDetails userDetails = this.loadUserByUsername(username);

        //Validamos si el usuario existe
        if (userDetails == null) {
            throw new BadCredentialsException("Invalid username or password");
        }

        //Validamos que la contraseña sea la correcta
        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }

        return new UsernamePasswordAuthenticationToken(username, userDetails.getPassword(), userDetails.getAuthorities());

    }
}
