package com.ecw.rcm.configure;

import com.ecw.rcm.filters.EcwUsernamePasswordAuthFilter;
import com.ecw.rcm.service.CustomDetailsService;
import com.ecw.rcm.utils.CustomPasswordEncoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomDetailsService customDetailsService;

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        // authentication manager (see below)
      auth.userDetailsService(customDetailsService).passwordEncoder(passwordEncoder());


    }


    @Override
    protected void configure(final HttpSecurity http) throws Exception {


        // http builder configurations for authorize requests and form login (see below)

        String []str={"/js/**","/img/**","/css/**","/login.html","/loginData/**","/loginData/key","/loginData/pubKey","/login","/loginProcess"};
        http.csrf().disable();

        http.authorizeRequests()
                .antMatchers(str)
                .permitAll()
                .anyRequest()
                .authenticated();

        http.formLogin().loginPage("/login.html").failureUrl("/login.html?error=2").loginProcessingUrl("/processLoginRequest")
               // .usernameParameter("username")
                //.passwordParameter("password")
                .defaultSuccessUrl("/home.html", true).permitAll();

        http.addFilterBefore(authenticationFilter(), EcwUsernamePasswordAuthFilter.class);

        http.logout()
                .logoutUrl("/perform_logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID");
    /*    http.addFilterBefore(authenticationFilter(),
                EcwUsernamePasswordAuthFilter.class)
                .authorizeRequests()
                 .antMatchers(str)
                .permitAll()
                 .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login.html")
                .failureUrl("/login.html")
        ;
*/
    }

    public EcwUsernamePasswordAuthFilter  authenticationFilter() throws Exception {
        EcwUsernamePasswordAuthFilter ecwUsernamePasswordAuthFilter = new EcwUsernamePasswordAuthFilter();
        ecwUsernamePasswordAuthFilter.setAuthenticationManager(authenticationManagerBean());
        ecwUsernamePasswordAuthFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler());

        return ecwUsernamePasswordAuthFilter;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring();
    }
   @Override
   @Bean
   public AuthenticationManager authenticationManagerBean() throws Exception {
       return super.authenticationManagerBean();
   }

    @Bean
    @Primary
    public PasswordEncoder passwordEncoder() {
        return new CustomPasswordEncoder();
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        AuthenticationSuccessHandler authenticationSuccessHandler = new AuthenticationSuccessHandler() {
            RedirectStrategy redirectStrategy1 = new DefaultRedirectStrategy();
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                redirectStrategy1.sendRedirect(request, response,"home.html");
            }
        };

        return authenticationSuccessHandler;
    }




}