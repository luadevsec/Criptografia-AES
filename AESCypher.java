import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class AESCypher {
    public static String encrypt(String algorithm, String input, SecretKey key,
            IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String algorithm, String cipherText, SecretKey key,
            IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException {

        String algorithm = "AES/CBC/PKCS5Padding";
        String keyString = "12345";
        String ivString = "im Lunna cipher L"; // IV de 16 bytes

        // Garantir que a chave tenha o comprimento correto
        byte[] keyBytes = Arrays.copyOf(keyString.getBytes(), 16);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        // Preparar o IV
        byte[] ivBytes = Arrays.copyOf(ivString.getBytes(), 16);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        String input = "Hello, World!";
        String cipherText = encrypt(algorithm, input, key, iv);
        System.out.println("Ciphertext: " + cipherText);
        String plainText = decrypt(algorithm, cipherText, key, iv);
        System.out.println("Plaintext: " + plainText);
    }
}

