package dev.igorsily.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import dev.igorsily.core.configs.JwtConfiguration;
import dev.igorsily.core.models.User;
import dev.igorsily.token.creator.TokenCreator;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    private final JwtConfiguration jwtConfiguration;

    private final TokenCreator tokenCreator;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JwtConfiguration jwtConfiguration, TokenCreator tokenCreator) {
        this.authenticationManager = authenticationManager;
        this.jwtConfiguration = jwtConfiguration;
        this.tokenCreator = tokenCreator;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        User user = null;
        try {

            user = new ObjectMapper().readValue(request.getInputStream(), User.class);

        } catch (IOException e) {

            e.printStackTrace();
        }

        if (user == null) throw new UsernameNotFoundException("");

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword(), Collections.emptyList());

        usernamePasswordAuthenticationToken.setDetails(user);

        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);

    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication auth)  {
        SignedJWT signedJWT;
            signedJWT = tokenCreator.createSignedJWT(auth);
            String encryptToken = tokenCreator.encryptToken(signedJWT);
            logger.info("TOKEN GERADO COM SUCESSO" + encryptToken);


        response.addHeader("Access-Control-Expose-Headers",
                "XSRF-TOKEN," + jwtConfiguration.getHeader().getName());

        response.addHeader(jwtConfiguration.getHeader().getName(), jwtConfiguration.getHeader().getPrefix() + encryptToken);

    }

}
