package com.ecw.rcm.configure;

import com.ecw.rcm.filters.EcwUsernamePasswordAuthFilter;
import com.ecw.rcm.service.CustomDetailsService;
import com.ecw.rcm.utils.CustomPasswordEncoder;
import com.ecw.rcm.utils.EcwHashUtill;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Pattern;

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
/*        http.authorizeRequests()
                .antMatchers("/", "/resources/**","/resources/static/**")
                .permitAll()
                .antMatchers( "/css/**","/js/**","/img/**")
                .permitAll()
                .antMatchers("/login")
                .permitAll()
                .antMatchers("/**")
                .hasAnyRole("ADMIN", "USER")
                .and()
                .formLogin()
                .loginPage("/login.html")
                .defaultSuccessUrl("/home.html")
                .failureUrl("/login?error=true")
                .permitAll()
                .and()
                .logout()
                .logoutSuccessUrl("/login?logout=true")
                .invalidateHttpSession(true)
                .permitAll()
                .and()
                .csrf()
                .disable();
*/
        String []str={"/js/**","/img/**","/css/**","/login.html","/loginData/**","/loginData/key","/loginData/pubKey"};
        http.csrf().disable();



        http.addFilterBefore(authenticationFilter(),
                EcwUsernamePasswordAuthFilter.class)
                .authorizeRequests()
                 .antMatchers(str)
                .permitAll()
                 .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login.html")
                //.loginProcessingUrl("/loginProcess")
                .successForwardUrl("/home.html");


      /*  http.authorizeRequests().anyRequest().authenticated().and().sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.NEVER);
*/
    }

    public EcwUsernamePasswordAuthFilter  authenticationFilter() throws Exception {
        EcwUsernamePasswordAuthFilter filter = new EcwUsernamePasswordAuthFilter();
        filter.setAuthenticationManager(authenticationManagerBean());
        //filter.setAuthenticationFailureHandler(failureHandler());
        return filter;
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


}