import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;


public class Main {

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        SecureRandom sr = new SecureRandom();
        byte[] key = new byte[16];
        sr.nextBytes(key); // 128 bit key
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector); // 16 bytes IV
        System.out.println("Random key=" + Util.bytesToHex(key));
        System.out.println("initVector=" + Util.bytesToHex(initVector));
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);

        Path dir = Paths.get("/Users/kuba/Desktop/po");

        final Path sourcePath = Paths.get("/Users/kuba/Desktop/przed/test.txt");

        final Path encryptedPath = dir.resolve("test-encrypted");

        final Path decryptedPath = dir.resolve("test-decrypted");


        encrypt(cipher, sourcePath,encryptedPath, skeySpec, iv);

        decrypt(cipher,skeySpec,iv,encryptedPath,decryptedPath);

    }
    public static void encrypt(Cipher cipher, Path sourcePath, Path encryptedPath, SecretKeySpec skeySpec, IvParameterSpec iv) throws InvalidAlgorithmParameterException, InvalidKeyException {

        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        try (InputStream fin = Files.newInputStream(sourcePath);
             OutputStream fout = Files.newOutputStream(encryptedPath);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
             }) {

            final byte[] bytes = new byte[1024];

            for(int length=fin.read(bytes); length!=-1; length = fin.read(bytes)){
                cipherOut.write(bytes, 0, length);
            }
            System.out.println();
            System.out.println("Encryption finished, saved at " + encryptedPath);


        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }

    public static void decrypt(Cipher cipher, SecretKeySpec skeySpec, IvParameterSpec iv, Path encryptedPath, Path decryptedPath) throws InvalidAlgorithmParameterException, InvalidKeyException {
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        try(InputStream encryptedData = Files.newInputStream(encryptedPath);
            CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
            OutputStream decryptedOut = Files.newOutputStream(decryptedPath)){
            final byte[] bytes = new byte[1024];
            for(int length=decryptStream.read(bytes); length!=-1; length = decryptStream.read(bytes)){
                decryptedOut.write(bytes, 0, length);
            }
            System.out.println();
            System.out.println("Decryption finished, saved at " + decryptedPath);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }
}

