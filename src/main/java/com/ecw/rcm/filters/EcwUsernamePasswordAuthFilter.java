package com.ecw.rcm.filters;

import com.ecw.rcm.security.SecurityHelper;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public class EcwUsernamePasswordAuthFilter extends UsernamePasswordAuthenticationFilter {

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        SecurityHelper sh=new SecurityHelper();
        if (!("POST").equalsIgnoreCase(request.getMethod())) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }


        String iv= request.getParameter("value");
        String key=request.getParameter("key");
        String strUserName = request.getParameter("doctorIDVal");
        String password = request.getParameter("password");

        String []keyVal=sh.getNewKey(key,iv,"");

        key=keyVal[0];
        iv=keyVal[1];

        strUserName=(strUserName==null)?"": SecurityHelper.decryptValue(strUserName.trim(),key, iv);

        password=(password==null)?"":SecurityHelper.decryptValue(password.trim(),key, iv);


        // Proceed for Spring security login Authentication
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(strUserName, password);

        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);


        // Get Authentication information
        Authentication auth = null;
        try {
            auth = this.getAuthenticationManager().authenticate(authRequest);
        } catch (AuthenticationException ex) {
            ex.printStackTrace();
                /*try {
                    WebApplicationContextUtils.getWebApplicationContext(session.getServletContext());
                    AuthenticationFailureHandler afh = new AuthenticationFailureHandler();
                    afh.onAuthenticationFailure(request, response, ex);
                    int sessionErrorCode = isAbsSessionTimeout ? 12 : 2;
                    request.setAttribute(SESSION_ERROR_CODE, sessionErrorCode);
                } catch (ServletException | IOException e) {
                    request.setAttribute(SESSION_ERROR_CODE, 9);
                }*/

        }
        return auth;


    }



}
