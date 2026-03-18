package org.wso2.carbon.identity.openid4vc.presentation.did.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.util.Collections;
import java.util.Set;

/**
 * A custom Ed25519 JWSSigner that relies on Bouncy Castle directly.
 */
public class BCEd25519Signer implements JWSSigner {

    private final OctetKeyPair privateKey;

    private BCEd25519Signer(OctetKeyPair privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Creates a new BCEd25519Signer.
     *
     * @param privateKey The Ed25519 private key.
     * @return A new BCEd25519Signer instance.
     * @throws JOSEException If the key is invalid.
     */
    public static BCEd25519Signer create(OctetKeyPair privateKey) throws JOSEException {
        if (!"Ed25519".equals(privateKey.getCurve().getName())) {
            throw new JOSEException("The key type must be Ed25519");
        }
        if (privateKey.getD() == null) {
            throw new JOSEException("The private key 'd' parameter is missing");
        }
        return new BCEd25519Signer(privateKey);
    }

    @Override
    public Base64URL sign(final JWSHeader header, final byte[] signingInput) throws JOSEException {

        // Check compatibility
        if (!supportedJWSAlgorithms().contains(header.getAlgorithm())) {
            throw new JOSEException("Unsupported algorithm: " + header.getAlgorithm());
        }

        try {
            // Extract private key bytes from JWK
            byte[] privateKeyBytes = privateKey.getD().decode();

            // Initialize Bouncy Castle Ed25519 signer
            Ed25519PrivateKeyParameters privateKeyParams = new Ed25519PrivateKeyParameters(privateKeyBytes, 0);
            Ed25519Signer signer = new Ed25519Signer();
            signer.init(true, privateKeyParams);
            signer.update(signingInput, 0, signingInput.length);

            // Sign the input
            byte[] signature = signer.generateSignature();
            return Base64URL.encode(signature);

        } catch (Exception e) {
            throw new JOSEException(e.getMessage(), e);
        }
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Collections.singleton(JWSAlgorithm.EdDSA);
    }

    @Override
    public com.nimbusds.jose.jca.JCAContext getJCAContext() {
        return new com.nimbusds.jose.jca.JCAContext();
    }
}
