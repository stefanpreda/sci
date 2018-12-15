package algorithm;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Blowfish {

    private SecretKey secretKey;
    private String IV = "12345678";

    public String runTestEncrypt(String input) {
        try {
            // sign the message
            return this.encrypt(input);

            } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String runTestDecrypt(String encrypted) {
        try {
            return decrypt(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
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
        this.secretKey = new SecretKeySpec(tmp.getEncoded(), "Blowfish");
    }

    private String encrypt(String secret) {
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), "Blowfish");

        try {
            Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new javax.crypto.spec.IvParameterSpec(IV.getBytes()));
            byte[] encoding = cipher.doFinal(secret.getBytes());
            return DatatypeConverter.printBase64Binary(encoding);

        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    private String decrypt(String secret) {
        // Decode Base64
        byte[] ciphertext = DatatypeConverter.parseBase64Binary(secret);
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), "Blowfish");

        // Decrypt
        try {
            Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new javax.crypto.spec.IvParameterSpec(IV.getBytes()));
            byte[] message = cipher.doFinal(ciphertext);

            return new String(message);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchPaddingException | BadPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }
}