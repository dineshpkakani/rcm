package com.ecw.rcm.controller;

import com.ecw.rcm.service.LoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/loginData")
public class loginController {

    @Autowired
    LoginService loginServiceObj;

    @PostMapping("/pubKey")
    public ResponseEntity<String> getPubKey(){
        return ResponseEntity.ok(loginServiceObj.getPubKey());
    }

}
