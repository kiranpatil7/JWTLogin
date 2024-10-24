package com.security.jwt.Config;

import com.security.jwt.Jwt.AuthEntryPointJwt;
import com.security.jwt.Jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    DataSource dataSource;
    @Autowired
    AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtFilter(){
        return  new AuthTokenFilter();
    }
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

               http.authorizeHttpRequests((requests) -> requests
                                                       .requestMatchers("/h2-console/**").permitAll()
                                                       .requestMatchers("/api/login").permitAll()
                                                       .anyRequest().authenticated());
                      http.sessionManagement(session-> session
                                                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
                      http.exceptionHandling(exception ->exception.authenticationEntryPoint(unauthorizedHandler));
                      http.headers(header -> header.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)); //to display the frame with login
                      http.csrf(csrf ->csrf.disable());
                      http.addFilterBefore(authenticationJwtFilter(), UsernamePasswordAuthenticationFilter.class);

                      return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){
//        UserDetails user1 = User.withUsername("kiran")
//                                        .password("kiran@123")
//                                        .roles("USER").build();
//        UserDetails admin1 = User.withUsername("Don")
//                .password("don@123")
//                .roles("ADMIN").build();

//        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
//         jdbcUserDetailsManager.createUser(user1);
//        jdbcUserDetailsManager.createUser(admin1);
//        return jdbcUserDetailsManager;
        return new JdbcUserDetailsManager(dataSource);
       // return new InMemoryUserDetailsManager(user1, admin1);
    }

    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService){
        return args -> {
            JdbcUserDetailsManager jdbcUserDetailsManager =(JdbcUserDetailsManager)userDetailsService;
            UserDetails user1 = User.withUsername("kiran")
                                        .password(passwordEncoder().encode("kiran@123"))
                                        .roles("USER").build();
        UserDetails admin1 = User.withUsername("Don")
                .password(passwordEncoder().encode("don@123"))
                .roles("ADMIN").build();
         JdbcUserDetailsManager JdbcManager = new JdbcUserDetailsManager(dataSource);
            JdbcManager.createUser(user1);
            JdbcManager.createUser(admin1);
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder)
            throws Exception{
        return builder.getAuthenticationManager();
    }

}
