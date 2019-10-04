package com.cloud.oauth2;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
	
	@Autowired   
	private AuthenticationManager authenticationManager;   
	@Autowired   
	private UserDetailsService userDetailsService;

	@Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        // 允许表单认证
        security.allowFormAuthenticationForClients()
        		.tokenKeyAccess("permitAll()")//公开/oauth/token的接口
                .checkTokenAccess("isAuthenticated()");
    }
	
	@Override   
	public void configure(ClientDetailsServiceConfigurer clients) throws      
	Exception {     
		String finalSecret = "{bcrypt}" + new BCryptPasswordEncoder().encode("secretcode");
		
		clients.inMemory()        
		.withClient("myclient")        
		.secret(finalSecret)        
		.authorizedGrantTypes("refresh_token", "password", "client_credentials")
		.scopes("read","write");    
	} 
	
	@Override    
	public void configure(AuthorizationServerEndpointsConfigurer endpoints)   throws Exception {    
		endpoints
		.authenticationManager(authenticationManager)               
		.userDetailsService(userDetailsService);    
	} 

	
}
