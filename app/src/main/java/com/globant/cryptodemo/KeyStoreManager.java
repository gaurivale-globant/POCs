package com.globant.cryptodemo;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

public class KeyStoreManager {
    private static final String KEY_STORE_TYPE = "AndroidKeyStore";
    private final String TAG = KeyStoreManager.class.getName();
    private KeyStore keyStore;
    private Context context;

    public KeyStoreManager(Context context) {
        try {
            this.context = context;
            keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
            keyStore.load(null);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
        }
    }

    public void createNewKeys(String strAlias) {
        try {
            Calendar start = Calendar.getInstance();
            Calendar end = Calendar.getInstance();
            end.add(Calendar.YEAR, 10);

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", KEY_STORE_TYPE);

            KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                    .setAlias(strAlias)
                    .setSubject(new X500Principal("CN=OPENBANK, O=Android Authority"))
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();

            keyPairGenerator.initialize(spec);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            Cipher cipher = getCipher();
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        } catch (Exception e) {
        }
    }

    public String encryptString(String textToEncrypt, String strAlias) {
        try {
            PublicKey publicKey = keyStore.getCertificate(strAlias).getPublicKey();
            if (publicKey == null) {
                return null;
            }
            Cipher input = getCipher();
            input.init(Cipher.ENCRYPT_MODE, publicKey);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, input);
            cipherOutputStream.write(textToEncrypt.getBytes("UTF-8"));
            cipherOutputStream.close();

            byte[] vals = outputStream.toByteArray();

            return Base64.encodeToString(vals, Base64.DEFAULT);

        } catch (Exception e) {
            return null;
        }
    }

    public String decryptString(String textToDecrypt, String strAlias) {
        try {
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(strAlias, null);
            if (privateKey == null) {
                return null;
            }
            Cipher output = getCipher();
            output.init(Cipher.DECRYPT_MODE, privateKey);
            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(Base64.decode(textToDecrypt, Base64.DEFAULT)), output);
            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte) nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i);
            }

            return new String(bytes, 0, bytes.length, "UTF-8");
        } catch (Exception e) {
            return null;
        }
    }

    private Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        //This cipher algorithm is supported from API level 18+, so no need to add OS based conditions.
        //https://developer.android.com/training/articles/keystore.html
        return Cipher.getInstance("RSA/ECB/PKCS1Padding");
    }
}
