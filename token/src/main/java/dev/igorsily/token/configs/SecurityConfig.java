package dev.igorsily.token.configs;

import dev.igorsily.core.configs.JwtConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.cors.CorsConfiguration;

import javax.servlet.http.HttpServletResponse;

public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtConfiguration jwtConfiguration;

    public SecurityConfig(JwtConfiguration jwtConfiguration) {
        this.jwtConfiguration = jwtConfiguration;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable().cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues())
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling().authenticationEntryPoint((req, res, err) -> res.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .and()
                .authorizeRequests().antMatchers(jwtConfiguration.getUrlLogin()).permitAll()
                .antMatchers("/course/admin/**").hasRole("ADMIN")
                .anyRequest().permitAll();
    }
}
