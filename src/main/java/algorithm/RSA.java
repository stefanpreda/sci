package algorithm;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;


public class RSA {
    private PublicKey pubKey;
    private PrivateKey privateKey;

    public byte[] runTestEncrypt(String input) {
        try {
            // sign the message
            byte [] signed = this.encrypt(privateKey, input);

            return signed;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String runTestDecrypt(byte[] encrypted) {
        try {
            return new String(decrypt(pubKey, encrypted));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public void buildKeyPair() {
        //256 Bytes
        final int keySize = 2048;
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        this.pubKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
    }

    private byte[] encrypt(PrivateKey privateKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(message.getBytes());
    }

    private byte[] decrypt(PublicKey publicKey, byte [] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        return cipher.doFinal(encrypted);
    }
}
