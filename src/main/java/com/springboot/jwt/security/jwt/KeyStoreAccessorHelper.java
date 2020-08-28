package com.springboot.jwt.security.jwt;

import com.google.common.io.Resources;
import com.springboot.jwt.constants.AuthenticationConstants;
import com.springboot.jwt.exception.ServiceException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class KeyStoreAccessorHelper {

    private static final Logger log = LogManager.getLogger(KeyStoreAccessorHelper.class);

    private final KeyStore keyStore;
    private final String path;
    private final String keystorePassword;
    private String privateKeyStorePassword;


    public KeyStoreAccessorHelper(String path, String keystorePassword) throws ServiceException {
        this.path = path;
        this.keystorePassword = keystorePassword;
        this.privateKeyStorePassword = keystorePassword;


        log.info("Attempting to load keystore from path {}", path);

        try (InputStream inputStream = Resources.getResource("identity-new.jks").openStream()) {
            if (null == inputStream) {
                log.debug("Keystore from path {} could not be loaded", this.path);
                throw new ServiceException(new StringBuilder().append("KeyStore from path ").append(path).append(" could not be loaded").toString(),new Exception().fillInStackTrace());
            }

            this.keyStore = KeyStore.getInstance("JKS");
            this.keyStore.load(inputStream, keystorePassword.toCharArray());

        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new ServiceException("Failed to load keystore from " + path, e);
        }

    }

    public KeyStoreAccessorHelper(String path, String keyStorePassword, String privateKeyStorePassword)
            throws ServiceException {
        this(path, keyStorePassword);
        this.privateKeyStorePassword = privateKeyStorePassword;
    }

    public KeyStore getKeyStore() {
        return this.keyStore;
    }

    public PrivateKey getPrivateKey(String alias) throws ServiceException {

        log.info("Loading Private Key {} from keystore using same password as keystore's", alias);

        String password;

        if (this.privateKeyStorePassword.equals(this.keystorePassword)) {
            password = this.keystorePassword;
        } else {
            password = this.privateKeyStorePassword;
        }

        PrivateKey key;
        try {
            key = (PrivateKey) this.keyStore.getKey(alias, password.toCharArray());

            if (null == key) {
                throw new ServiceException("Failed to find private key " + alias + AuthenticationConstants.FROM_KEYSTORE + this.path
                        + " using same password as keystore's");
            }

            return key;

        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new ServiceException("Failed to find private key " + alias + AuthenticationConstants.FROM_KEYSTORE+ this.path
                    + " using same password as keystore's", e);
        }

    }

    public PublicKey getPublicKey(String alias) throws ServiceException {

        try {
            log.debug("Loading public key {} from keystore {}", alias, this.path);
            Certificate cert = this.keyStore.getCertificate(alias);

            if (null == cert) {
                throw new ServiceException("Failed to find certificate " + alias + AuthenticationConstants.FROM_KEYSTORE + this.path);
            }

            PublicKey key = cert.getPublicKey();

            if (null == key) {
                throw new ServiceException("Failed to get key from " + alias + AuthenticationConstants.FROM_KEYSTORE + this.path);
            }

            return key;

        } catch (KeyStoreException e) {
            throw new ServiceException("Failed to find public key " + alias + AuthenticationConstants.FROM_KEYSTORE + this.path, e);
        }

    }

}
