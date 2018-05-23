package com.globant.cryptodemo;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


/*        KeyStoreManager keyStoreManager = new KeyStoreManager(this);
        keyStoreManager.createNewKeys("TestKey");
        String encryptedStr = keyStoreManager.encryptString("This is my first encryption algo.", "TestKey");
        System.out.println("encryptedStr: " + encryptedStr);
        String decryptedStr = keyStoreManager.decryptString(encryptedStr, "TestKey");
        System.out.println("decryptedStr: " + decryptedStr);*/

        String plainText = "this is plain text to be encrypted!!!";

        plainText = "English, Español, Pусский, 简体中文, Kreyòl Franse, 한국어";

        System.out.println("CRYPTO:plainText: " + plainText);
        String encData = CryptoUtils.encryptData(this, plainText);
        System.out.println("CRYPTO:encData: " + encData);
        String decData = CryptoUtils.decryptData(this, encData);
        System.out.println("CRYPTO:decData: " + decData);

    }
}
