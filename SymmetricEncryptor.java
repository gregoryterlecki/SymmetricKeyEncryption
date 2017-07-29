import java.util.Scanner;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;

public class SymmetricEncryptor {

  public static final String KEY_FILE_NAME = "key";
  public static final String ALGORITHM     = "AES";
  public static final String PADDING_TYPE  = "/CBC/PKCS5Padding";
  public static final String KEY_FORMAT    = "RAW";

  private Key key;

  public SymmetricEncryptor() throws Exception{
    this.key = generateKey();
  }

  public SymmetricEncryptor(Key key){
    this.key = key;
  }

  public static Key generateKey() throws Exception{
    KeyGenerator generator = KeyGenerator.getInstance(ALGORITHM);
    SecretKey key = generator.generateKey();
    return key;
  }

  public static byte[] generateInitVector(){
    SecureRandom rand = new SecureRandom();
    byte[] initVector = new byte[16];
    rand.nextBytes(initVector);
    return initVector;
  }

  public String encrypt(String plainText) throws Exception{
    String cipherText = encrypt(plainText, generateInitVector());
    return cipherText;
  }

  public String encrypt(String plainText, byte[] initVector) throws Exception{

    Cipher cipher = Cipher.getInstance(key.getAlgorithm() + PADDING_TYPE);
    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(initVector));
    byte[] encrypted = cipher.doFinal(plainText.getBytes());

    String cipherText = Base64.encodeBase64String(initVector);
    cipherText += "::";
    cipherText += Base64.encodeBase64String(encrypted);

    return cipherText;
  }

  public String decrypt(String cipherText) throws Exception{

    String[] halves = cipherText.split("::");
    byte[] initVector = Base64.decodeBase64(halves[0]);
    byte[] encrypted = Base64.decodeBase64(halves[1]);

    Cipher cipher = Cipher.getInstance(key.getAlgorithm() + PADDING_TYPE);
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(initVector));
    return new String(cipher.doFinal(encrypted));
  }

  private void setKey(Key key){
    this.key = key;
  }

  private Key getKey(){
    return this.key;
  }

  public static void main(String[] args) throws Exception{

    SymmetricEncryptor encryptor = new SymmetricEncryptor();

    String decrypted = "";
    String encrypted = "";

    System.out.println("Enter the plain text to encrypt: ");
    Scanner scan = new Scanner(System.in);
    decrypted = scan.nextLine();
    System.out.println("\n\nplainText:           " + decrypted);
    encrypted = encryptor.encrypt(decrypted);
    System.out.println("cipherText:          " + encrypted);
    System.out.println("Secret Key:          " + Base64.encodeBase64(encryptor.getKey().getEncoded()));
    System.out.println("decrypted plainText: " + encryptor.decrypt(encrypted));

  }

}
