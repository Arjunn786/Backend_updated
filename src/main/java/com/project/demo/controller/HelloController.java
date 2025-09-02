package com.project.demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api")
public class HelloController {

    @GetMapping("/hello")
    public String hello(Principal principal) {
        // Principal will be null if the user is not authenticated
        return "Hello, " + principal.getName() + "! This is a protected resource.";
    }
}