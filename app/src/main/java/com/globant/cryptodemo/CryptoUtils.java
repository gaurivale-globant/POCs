package com.globant.cryptodemo;

import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import static java.security.spec.RSAKeyGenParameterSpec.F4;

public class CryptoUtils {

    private static final String TAG = CryptoUtils.class.getSimpleName();

    private static final String PROVIDER_ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String PROVIDER_ANDROID_OPEN_SSL = "AndroidOpenSSL";
    private static final String KEYSTORE_ALIAS_MYMTA = "MyMta";
    private static final String CERTIFICATE_NAME_MYMTA = "MyMta";
    private static final String TRANSFORMATION_TYPE_RSA_ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";
    private static final String CHARACTER_SET_UTF16 = "UTF-16";

    private static final int CERTIFICATE_VALIDITY = 25;

    private static final String ALGORITHM_RSA = "RSA";

    private static final int CERTIFICATE_SERIAL_NUMBER = 1337;
    private static final int KEY_SIZE = 1024;


    //MTAMOBILEAPP

    private CryptoUtils() {

    }

    /**
     * Creates a public and private key and stores it using the Android Key Store, so that only
     * this application will be able to access the keys.
     */
    private static void createKeys1(Context context) throws NoSuchProviderException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        // BEGIN_INCLUDE(create_valid_dates)
        // Create a start and end time, for the validity range of the key pair that's about to be
        // generated.
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, CERTIFICATE_VALIDITY);
        //END_INCLUDE(create_valid_dates)

        // BEGIN_INCLUDE(create_keypair)
        // Initialize a KeyPair generator using the the intended algorithm (in this example, RSA
        // and the KeyStore.  This example uses the AndroidKeyStore.
        KeyPairGenerator kpGenerator = KeyPairGenerator
                .getInstance(ALGORITHM_RSA,
                        PROVIDER_ANDROID_KEY_STORE);
        // END_INCLUDE(create_keypair)

        // BEGIN_INCLUDE(create_spec)
        // The KeyPairGeneratorSpec object is how parameters for your key pair are passed
        // to the KeyPairGenerator.
        AlgorithmParameterSpec spec;
        X500Principal x500Principal = new X500Principal("CN=" + KEYSTORE_ALIAS_MYMTA + ", O=Android Authority");

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            // Below Android M, use the KeyPairGeneratorSpec.Builder.

            spec = new KeyPairGeneratorSpec.Builder(context)
                    // You'll use the alias later to retrieve the key.  It's a key for the key!
                    .setAlias(KEYSTORE_ALIAS_MYMTA)
                    //.setKeySize(KEY_SIZE)
                    // The subject used for the self-signed certificate of the generated pair
                    .setSubject(x500Principal)
                    // The serial number used for the self-signed certificate of the
                    // generated pair.
                    .setSerialNumber(BigInteger.ONE)
                    // Date range of validity for the generated pair.
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();


        } else {
            // On Android M or above, use the KeyGenparameterSpec.Builder and specify permitted
            // properties  and restrictions of the key.
            spec = new KeyGenParameterSpec.Builder(KEYSTORE_ALIAS_MYMTA, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setAlgorithmParameterSpec(
                            new RSAKeyGenParameterSpec(1024, F4))
                    .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .setCertificateSubject(x500Principal)
                    //.setKeySize(KEY_SIZE)
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .setCertificateNotBefore(start.getTime())
                    .setCertificateNotAfter(end.getTime())
                    .build();

        }

        kpGenerator.initialize(spec);

        KeyPair kp = kpGenerator.generateKeyPair();
        // END_INCLUDE(create_spec)
    }


    public static byte[] encrypt1(Context context, String inputData) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2) {
            return null;
        }

        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(PROVIDER_ANDROID_KEY_STORE);
        } catch (KeyStoreException e) {
            return null;
        }
        try {
            keyStore.load(null);
            if (!keyStore.containsAlias(KEYSTORE_ALIAS_MYMTA)) {
                createKeys1(context);
            }
        } catch (Exception e) {
            return null;
        }

        // Encrypt the text
        String plainText = "This text is supposed to be a secret!";


        Cipher inCipher = null;
        try {
            inCipher = Cipher.getInstance(TRANSFORMATION_TYPE_RSA_ECB_PKCS1_PADDING);
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (NoSuchPaddingException e) {
            return null;
        }
        try {
            inCipher.init(Cipher.ENCRYPT_MODE, keyStore.getCertificate(KEYSTORE_ALIAS_MYMTA).getPublicKey());
        } catch (InvalidKeyException | KeyStoreException e) {
            return null;
        }

        byte[] encryptedData = null;
        try {
            encryptedData = inCipher.doFinal(plainText.getBytes(CHARACTER_SET_UTF16));
        } catch (IllegalBlockSizeException e) {
            return null;
        } catch (BadPaddingException e) {
            return null;
        } catch (UnsupportedEncodingException e) {
            return null;
        }

        String encodedData = Base64.encodeToString(encryptedData, Base64.DEFAULT);
        Log.d(TAG, "encodedData: " + encodedData);

        Cipher outCipher = null;
        try {
            outCipher = Cipher.getInstance(TRANSFORMATION_TYPE_RSA_ECB_PKCS1_PADDING);
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (NoSuchPaddingException e) {
            return null;
        }
        try {
            outCipher.init(Cipher.DECRYPT_MODE, (PrivateKey) keyStore.getKey(KEYSTORE_ALIAS_MYMTA, null));
        } catch (InvalidKeyException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            return null;
        }

        try {
            byte[] decryptedData = outCipher.doFinal(Base64.decode(encodedData, Base64.DEFAULT));
            try {
                Log.d(TAG, "decrypted data: " + new String(decryptedData, CHARACTER_SET_UTF16));
            } catch (UnsupportedEncodingException e) {
                return null;
            }
        } catch (IllegalBlockSizeException e) {
            return null;
        } catch (BadPaddingException e) {
            return null;
        }

        return null;
    }

    public static byte[] decrypt1(Context context, String inputData) {
        return null;
    }


    public static String encryptData(Context context, String inputData) {

        KeyGenerator generator = null;
        try {
            generator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
        generator.init(128); // The AES key size in number of bits
        SecretKey secKey = generator.generateKey();

        Cipher aesCipher = null;
        try {
            aesCipher = Cipher.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (NoSuchPaddingException e) {
            return null;
        }
        try {
            aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
        } catch (InvalidKeyException e) {
            return null;
        }

        byte[] byteCipherText;
        try {
            byteCipherText = aesCipher.doFinal(inputData.getBytes());
        } catch (IllegalBlockSizeException e) {
            return null;
        } catch (BadPaddingException e) {
            return null;
        } catch (/*UnsupportedEncoding*/Exception e) {
            return null;
        }

        String encodedData = Base64.encodeToString(byteCipherText, Base64.DEFAULT);

        String encodedKey = null;
        try {
            encodedKey = encrypt(context, secKey.getEncoded());
        } catch (/*UnsupportedEncoding*/Exception e) {
            return null;
        }

        return encodedKey + " " + encodedData;
    }

    public static String decryptData(Context context, String inputData) {

        String key = inputData.substring(0, inputData.indexOf(' '));
        byte[] decryptedKey = decrypt(context, key);
        SecretKey originalKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
        Cipher aesCipher = null;
        try {
            aesCipher = Cipher.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (NoSuchPaddingException e) {
            return null;
        }

        String data = inputData.substring(inputData.indexOf(' '));
        byte[] encData = Base64.decode(data, Base64.DEFAULT);

        try {
            aesCipher.init(Cipher.DECRYPT_MODE, originalKey);
        } catch (InvalidKeyException e) {
            return null;
        }
        byte[] bytePlainText = new byte[0];
        try {
            bytePlainText = aesCipher.doFinal(encData);
        } catch (IllegalBlockSizeException e) {
            return null;
        } catch (BadPaddingException e) {
            return null;
        }
        String plainText = new String(bytePlainText);

        return plainText;
    }


    private static void createKeys(Context context) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        Calendar startDate = Calendar.getInstance();
        Calendar endDate = Calendar.getInstance();
        endDate.add(Calendar.YEAR, CERTIFICATE_VALIDITY);

        AlgorithmParameterSpec spec;
        X500Principal x500Principal = new X500Principal("CN=" + KEYSTORE_ALIAS_MYMTA + ", O=Android Authority");

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {

            spec = new KeyPairGeneratorSpec.Builder(context)
                    .setAlias(KEYSTORE_ALIAS_MYMTA)
                    //.setKeySize(KEY_SIZE)
                    .setSubject(x500Principal)
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(startDate.getTime())
                    .setEndDate(endDate.getTime())
                    .build();


        } else {
            spec = new KeyGenParameterSpec.Builder(KEYSTORE_ALIAS_MYMTA, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(KEY_SIZE, F4))
                    .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .setCertificateSubject(x500Principal)
                    //.setKeySize(KEY_SIZE)
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .setCertificateNotBefore(startDate.getTime())
                    .setCertificateNotAfter(endDate.getTime())
                    .build();

        }

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_RSA, PROVIDER_ANDROID_KEY_STORE);
        keyPairGenerator.initialize(spec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
    }


    public static String encrypt(Context context, byte[] inputData) {
        if (null == inputData || inputData.length <= 0) {
            return null;
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2) {
            try {
                return Base64.encodeToString(inputData, Base64.DEFAULT);
            } catch (/*UnsupportedEncoding*/Exception e) {
                return null;
            }
        }

        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(PROVIDER_ANDROID_KEY_STORE);
        } catch (KeyStoreException e) {
            return null;
        }
        try {
            keyStore.load(null);
            if (!keyStore.containsAlias(KEYSTORE_ALIAS_MYMTA)) {
                createKeys(context);
            }
        } catch (Exception e) {
            return null;
        }

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(TRANSFORMATION_TYPE_RSA_ECB_PKCS1_PADDING);
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (NoSuchPaddingException e) {
            return null;
        }
        try {
            cipher.init(Cipher.ENCRYPT_MODE, keyStore.getCertificate(KEYSTORE_ALIAS_MYMTA).getPublicKey());
        } catch (InvalidKeyException | KeyStoreException e) {
            return null;
        }

        byte[] encryptedData = null;
        try {
            encryptedData = cipher.doFinal(inputData);
        } catch (IllegalBlockSizeException e) {
            return null;
        } catch (BadPaddingException e) {
            return null;
        } catch (/*UnsupportedEncoding*/Exception e) {
            return null;
        }

        String encodedData = Base64.encodeToString(encryptedData, Base64.DEFAULT);

        return encodedData;
    }

    public static byte[] decrypt(Context context, String inputData) {
        if (TextUtils.isEmpty(inputData)) {
            return null;
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2) {
            try {
                return Base64.decode(inputData, Base64.DEFAULT);
            } catch (/*UnsupportedEncoding*/Exception e) {
                return null;
            }
        }

        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(PROVIDER_ANDROID_KEY_STORE);
        } catch (KeyStoreException e) {
            return null;
        }
        try {
            keyStore.load(null);
            if (!keyStore.containsAlias(KEYSTORE_ALIAS_MYMTA)) {
                createKeys(context);
            }
        } catch (Exception e) {
            return null;
        }

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(TRANSFORMATION_TYPE_RSA_ECB_PKCS1_PADDING);
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (NoSuchPaddingException e) {
            return null;
        }

        try {
            cipher.init(Cipher.DECRYPT_MODE, (PrivateKey) keyStore.getKey(KEYSTORE_ALIAS_MYMTA, null));
        } catch (InvalidKeyException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            return null;
        }

        try {
            byte[] decryptedData = cipher.doFinal(Base64.decode(inputData, Base64.DEFAULT));
            try {
                return decryptedData;
            } catch (/*UnsupportedEncoding*/Exception e) {
                return null;
            }
        } catch (IllegalBlockSizeException e) {
            return null;
        } catch (BadPaddingException e) {
            return null;
        }

    }


}
