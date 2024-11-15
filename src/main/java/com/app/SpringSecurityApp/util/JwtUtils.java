package com.app.SpringSecurityApp.util;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

//Clase utils de JWT
@Component
public class JwtUtils {

    @Value("${security.jwt.key.private}")
    private String privateKey;

    @Value("${security.jwt.user.generator}")
    private String userGenerator;

    //Metodo para crear token codificado
    public String createToken(Authentication authentication) {


        Algorithm algorithm = Algorithm.HMAC256(this.privateKey);

        //Obtenemos el usuario
        String username = authentication.getPrincipal().toString();

        //Obtenemos authorities y las separamos por coma con Collectors.joining
        String authorities = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));


        //Creamos el token
        String jwtToken = JWT.create()

                .withIssuer(userGenerator)

                //Pasamos el usuario
                .withSubject(username)

                //Pasamos las authorities
                .withClaim("authorities", authorities)

                //Asignamos fecha de creado
                .withIssuedAt(new Date())

                //Asignamos fecha de expiracion
                .withExpiresAt(new Date(System.currentTimeMillis() + 180000))

                //Asignamos ID
                .withJWTId(UUID.randomUUID().toString())

                //Asignamos tiempo de validez del token
                .withNotBefore(new Date(System.currentTimeMillis()))

                //Asignamos firma
                .sign(algorithm);

        return jwtToken;
    }

    //Verificar token y decodificar
    public DecodedJWT validateToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(this.privateKey);

            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(this.userGenerator)
                    .build();

            DecodedJWT decodedJWT = verifier.verify(token);
            return decodedJWT;

        } catch (JWTVerificationException exception) {
            throw new JWTVerificationException("Invalid token, not Authorized");
        }
    }

    //Extraemos el usuario del token
    public String extractUsername(DecodedJWT decodedJWT) {
        return decodedJWT.getSubject().toString();
    }

    //Extraer un claim del token
    public Claim getSpecificClaim(DecodedJWT decodedJWT, String claimName) {
        return decodedJWT.getClaim(claimName);
    }

    //Extraer todos los claims del token
    public Map<String, Claim> returnAllClaims(DecodedJWT decodedJWT) {
        return decodedJWT.getClaims();
    }
}
