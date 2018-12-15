package algorithm;

import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AES {

    private SecretKey secretKey;
    private byte[] iv;

    public byte[] runTestEncrypt(String input) {
        return this.encrypt(input);
    }

    public String runTestDecrypt(byte[] encryptedCipher) {
        return this.decrypt(encryptedCipher);
    }

    public void setKey() {
        SecretKeyFactory factory = null;
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        KeySpec spec = new PBEKeySpec("password".toCharArray(), salt, 65536, 256);
        SecretKey tmp = null;
        try {
            tmp = factory.generateSecret(spec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        this.secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

    }

    private byte[] encrypt(String strToEncrypt) {
        /* Encrypt the message. */
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            AlgorithmParameters params = cipher.getParameters();

            this.iv = params.getParameterSpec(IvParameterSpec.class).getIV();
            return cipher.doFinal(strToEncrypt.getBytes("UTF-8"));
        } catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException | InvalidParameterSpecException | InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    private String decrypt(byte[] ciphertext) {
        /* Decrypt the message, given derived key and initialization vector. */
        String plaintext = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

            plaintext = new String(cipher.doFinal(ciphertext), "UTF-8");
        } catch (UnsupportedEncodingException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return plaintext;
    }
}
