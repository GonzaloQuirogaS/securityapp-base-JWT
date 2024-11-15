package com.app.SpringSecurityApp.controller;

import com.app.SpringSecurityApp.controller.dto.AuthLoginRequest;
import com.app.SpringSecurityApp.controller.dto.AuthResponse;
import com.app.SpringSecurityApp.service.UserDetailServiceImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

//AuthController
@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    @Autowired
    private UserDetailServiceImpl userDetailService;


    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody @Valid AuthLoginRequest userRequest) {

        return new ResponseEntity<>(this.userDetailService.loginUser(userRequest), HttpStatus.OK);

    }

}
