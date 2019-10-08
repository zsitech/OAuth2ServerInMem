package com.cloud.oauth2;

import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Override   
	@Bean   
	public AuthenticationManager authenticationManagerBean() throws Exception{     
		return super.authenticationManagerBean();   		
	} 
	
	@Override   
	@Bean   
	public UserDetailsService userDetailsServiceBean() throws Exception {     
		return super.userDetailsServiceBean();   
	}
	
	// 必须设置，否则报这个错误：There is no PasswordEncoder mapped for the id “null”
	@Bean
    public BCryptPasswordEncoder passwordEncoder() {
        // 设置默认的加密方式
        return new BCryptPasswordEncoder();
    }
	
	@Override   
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {     
		auth.inMemoryAuthentication()
			.passwordEncoder(new BCryptPasswordEncoder()) // 必须要，不能少
    		.withUser("user").password(new BCryptPasswordEncoder().encode("123456")).roles("USER")
    		.and() 
    		.withUser("admin").password(new BCryptPasswordEncoder().encode("654321")).roles("USER", "ADMIN"); 
	}
	
	// 这个是必须的，要不验证不了
	@Override
    protected void configure(HttpSecurity http) throws Exception {  
        http.requestMatchers().anyRequest()
            .and()
            .authorizeRequests()
            .antMatchers("/oauth/*").permitAll()
            .and()
        	.authorizeRequests()
        	.antMatchers("/actuator/*").permitAll();	// 放开健康检查的节点权限   
    }
}
