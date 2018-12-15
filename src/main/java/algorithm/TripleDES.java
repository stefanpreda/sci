package algorithm;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class TripleDES {

    private SecretKey secretKey;

    public byte[] runTestEncrypt(String input) {
       return this.encrypt(input);
    }

    public String runTestDecrypt(byte[] encryptedCipher) {
        return this.decrypt(encryptedCipher);
    }

    public void setKey() {

        try {
            final MessageDigest md = MessageDigest.getInstance("md5");
            final byte[] digestOfPassword = md.digest("HG58YZ3CR9".getBytes("utf-8"));
            final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);

            secretKey = new SecretKeySpec(keyBytes, "DESede");
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private byte[] encrypt(String message) {
        final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        final Cipher cipher;
        byte[] cipherText = null;
        try {
            cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            final byte[] plainTextBytes = message.getBytes("utf-8");
            cipherText = cipher.doFinal(plainTextBytes);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchPaddingException e) {
            e.printStackTrace();
        }

        return cipherText;
    }

    private String decrypt(byte[] message) {
        final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        try {
            final Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            decipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            final byte[] plainText = decipher.doFinal(message);

            return new String(plainText, "UTF-8");
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | UnsupportedEncodingException | BadPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }
}
