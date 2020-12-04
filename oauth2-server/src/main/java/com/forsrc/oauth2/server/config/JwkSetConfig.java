package com.forsrc.oauth2.server.config;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

@Configuration
public class JwkSetConfig {

    @Value("${jwt.verifier-key}")
    String verifierKey;
    @Value("${jwt.signing-key}")
    String signingKey;

    @Bean
    public KeyPair keyPair() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {

        KeyFactory kf = KeyFactory.getInstance("RSA");

        String signing = signingKey.replace("-----BEGIN RSA PRIVATE KEY-----\n", "")
                .replace("-----END RSA PRIVATE KEY-----", "").replaceAll("\n", "");
        String verifier = verifierKey.replace("-----BEGIN PUBLIC KEY-----\n", "")
                .replace("-----END PUBLIC KEY-----", "").replaceAll("\n", "");

        byte[] encodedPrivateKey = Base64.getDecoder().decode(signing);

        ASN1Sequence primitive = (ASN1Sequence) ASN1Sequence.fromByteArray(encodedPrivateKey);
        Enumeration<?> e = primitive.getObjects();
        BigInteger v = ((ASN1Integer) e.nextElement()).getValue();

        int version = v.intValue();
        if (version != 0 && version != 1) {
            throw new IllegalArgumentException("wrong version for RSA private key");
        }
        BigInteger modulus = ((ASN1Integer) e.nextElement()).getValue();
        BigInteger publicExponent = ((ASN1Integer) e.nextElement()).getValue();
        BigInteger privateExponent = ((ASN1Integer) e.nextElement()).getValue();
        BigInteger prime1 = ((ASN1Integer) e.nextElement()).getValue();
        BigInteger prime2 = ((ASN1Integer) e.nextElement()).getValue();
        BigInteger exponent1 = ((ASN1Integer) e.nextElement()).getValue();
        BigInteger exponent2 = ((ASN1Integer) e.nextElement()).getValue();
        BigInteger coefficient = ((ASN1Integer) e.nextElement()).getValue();

        RSAPrivateKeySpec spec = new RSAPrivateKeySpec(modulus, privateExponent);

        PrivateKey privateKey = kf.generatePrivate(spec);
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(verifier));
        RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
        return new KeyPair(publicKey, privateKey);
    }

    @Bean
    public JWKSet jwkSet() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        RSAKey.Builder builder = new RSAKey.Builder((RSAPublicKey) keyPair().getPublic()).keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256).keyID("forsrc");
        return new JWKSet(builder.build());
    }
}
