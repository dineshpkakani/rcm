package com.ecw.rcm.service;

import com.ecw.rcm.security.SecurityHelper;
import org.springframework.stereotype.Service;

@Service
public class LoginService {


    public String getPubKey() {
        return  new SecurityHelper().getRSAPubKey();
    }
}
