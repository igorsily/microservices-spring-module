package dev.igorsily.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.igorsily.core.configs.JwtConfiguration;
import dev.igorsily.core.models.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Date;
import java.util.stream.Collectors;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    private final JwtConfiguration jwtConfiguration;

    @Autowired
    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JwtConfiguration jwtConfiguration) {
        this.authenticationManager = authenticationManager;
        this.jwtConfiguration = jwtConfiguration;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        User user = null;
        try {

            user = new ObjectMapper().readValue(request.getInputStream(), User.class);

        } catch (IOException e) {

            e.printStackTrace();
        }

        if (user == null)  throw new UsernameNotFoundException("");

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword(), Collections.emptyList() );

        usernamePasswordAuthenticationToken.setDetails(user);

        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);

    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication auth) throws IOException, ServletException {

    }

    private SignedJWT createSignedJWT(Authentication auth) {

        User user = (User) auth.getPrincipal();

        JWTClaimsSet jwtClaimsSet = createJWTClaimSet(auth, user);


        return null;
    }

    private JWTClaimsSet createJWTClaimSet(Authentication auth, User user){

        return new JWTClaimsSet.Builder()
                .subject(user.getUsername())
                .claim("authorities", auth.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .issuer("http://academy.devdojo")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + (jwtConfiguration.getExpiration() * 1000)))
                .build();
    }

    private KeyPair generateKeyPair(){
        KeyPairGenerator generator = null;
        try {
            generator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        assert generator != null;

        generator.initialize(2048);

        return generator.genKeyPair();
    }
}
