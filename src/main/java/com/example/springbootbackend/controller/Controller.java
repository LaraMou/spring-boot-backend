package com.example.springbootbackend.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
public class Controller {
    @GetMapping("/months")
    public List<String> welcomePage(){
        return Arrays.asList("Enero","Febrero","Marzo");
    }

    @GetMapping("/admin")
    public String adminPage(){
        return "Admin Page";
    }
}
