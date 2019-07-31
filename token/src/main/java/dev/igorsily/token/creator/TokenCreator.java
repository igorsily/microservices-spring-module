package dev.igorsily.token.creator;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.igorsily.core.configs.JwtConfiguration;
import dev.igorsily.core.models.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class TokenCreator {

    private final JwtConfiguration jwtConfiguration;

    @Autowired
    public TokenCreator(JwtConfiguration jwtConfiguration) {
        this.jwtConfiguration = jwtConfiguration;
    }


    public SignedJWT createSignedJWT(Authentication auth)  {

        User user = (User) auth.getPrincipal();

        JWTClaimsSet jwtClaimsSet = createJWTClaimSet(auth, user);

        KeyPair rsaKey = generateKeyPair();

        JWK jwk = new RSAKey.Builder((RSAPublicKey) rsaKey.getPublic()).keyID(UUID.randomUUID().toString()).build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .jwk(jwk).type(JOSEObjectType.JWT).build(), jwtClaimsSet);

        RSASSASigner rsassaSigner = new RSASSASigner(rsaKey.getPrivate());

        try {
            signedJWT.sign(rsassaSigner);
        } catch (JOSEException e) {
            e.printStackTrace();
        }

        return signedJWT;
    }

    private JWTClaimsSet createJWTClaimSet(Authentication auth, User user) {

        return new JWTClaimsSet.Builder()
                .subject(user.getUsername())
                .claim("authorities", auth.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .issuer("http://igorsily.dev")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + (jwtConfiguration.getExpiration() * 1000)))
                .build();
    }

    private KeyPair generateKeyPair() {
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

    public String encryptToken(SignedJWT signedJWT) {
        JWEObject jwt = null;
        try {
            DirectEncrypter directEncrypter = new DirectEncrypter(jwtConfiguration.getPrivateKey().getBytes());

            jwt =new JWEObject(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
                    .contentType("JWT").build(), new Payload(signedJWT));


            jwt.encrypt(directEncrypter);
        } catch (JOSEException e) {
            e.printStackTrace();
        }

        assert jwt != null;
        return jwt.serialize();
    }


}
