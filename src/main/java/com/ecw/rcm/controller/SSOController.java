package com.ecw.rcm.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/sso")
public class SSOController {

    public ResponseEntity getSSODetails(String username){

        return  null;
    }
}
