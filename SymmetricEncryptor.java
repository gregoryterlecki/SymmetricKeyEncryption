import java.nio.file.Files;
import java.nio.file.Paths;

import java.io.File;
import java.io.FileWriter;
import java.util.Scanner;

import java.security.Key;
//import java.security.KeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

import javax.crypto.SecretKeyFactory;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.cli.*;


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

    Options options = new Options();

    Option decryptOpt = new Option("d", "decrypt", false, "Decrypt your message");
    decryptOpt.setRequired(false);

    Option genKeyOpt = new Option("g", "generate-key", false, "Generate a new key in " + KEY_FILE_NAME);
    genKeyOpt.setRequired(false);

    Option inTextFileOpt = Option.builder("i")
                                    .longOpt("plaintext-file")
                                    .desc("use text file as input")
                                    .hasArg()
                                    .argName("ptFile")
                                    .build();

    Option outTextFileOpt = Option.builder("o")
                                    .longOpt("plaintext-file")
                                    .desc("use text file as output")
                                    .hasArg()
                                    .argName("ptFile")
                                    .build();

    options.addOption(decryptOpt);
    options.addOption(inTextFileOpt);
    options.addOption(outTextFileOpt);
    options.addOption(genKeyOpt);

    CommandLineParser parser = new DefaultParser();
    HelpFormatter formatter = new HelpFormatter();
    CommandLine cmd = parser.parse(options, args);

    try {
      cmd = parser.parse(options, args);
    } catch (ParseException e) {
      System.out.println(e.getMessage());
      formatter.printHelp("utility-name", options);
      System.exit(1);
      return;
    }

    //instantiate encryptor class
    SymmetricEncryptor encryptor = new SymmetricEncryptor();
    String input  = "";
    String output = "";

    if(cmd.hasOption("g")){
      File keyFile = new File(KEY_FILE_NAME);
      FileWriter writer = new FileWriter(keyFile, false);
      writer.write(Base64.encodeBase64String(encryptor.getKey().getEncoded()));
      writer.flush();
      writer.close();

      System.out.println("your key: " + Base64.encodeBase64String(encryptor.getKey().getEncoded()));
      System.out.println("A new key was written to " + KEY_FILE_NAME);
      System.exit(0);
    }

    if(cmd.hasOption("i")){ /* gets the name of the input file */
      String inFileName = cmd.getOptionValue("i");
      try {
        input = new String(Files.readAllBytes(Paths.get(inFileName)));
      } catch (Exception e) {
        System.err.println("Error reading input file");
        System.exit(1);
      }
    } else { /* takes string as input from user using Scanner class */
      System.out.println("Enter the plain text to encrypt: ");
      Scanner scan = new Scanner(System.in);
      input = scan.next();
      System.out.println("The input entered is: " + input);
    }

    if(cmd.hasOption("o")){
      String outFileName = cmd.getOptionValue("o");
    } else { /* takes string as input from user using Scanner class */
      // System.out.println("Enter the plain text to encrypt");
      // Scanner scan = new Scanner(System.in);
      // String s = scan.next();
      // System.out.println("The plain text entered is: " + s);
    }



    //initialize SymmetricEncryptor class

    //take some text from the user to encrypt
    if(cmd.hasOption("d")){//decrypt mode\
      File keyFile = new File(KEY_FILE_NAME);
      if(!keyFile.exists()){
        System.out.println("Error: decrypt mode requires that the key is present in this directory");
        System.out.println("       the key should be in a file called \' key.txt \'");
        System.exit(1);
      }
      if(cmd.hasOption("i")){
        String inFileName = cmd.getOptionValue("i");
        try {
          input = new String(Files.readAllBytes(Paths.get(inFileName)));
        } catch (Exception e) {
          System.err.println("Error reading input file");
          System.exit(1);
        }
      } else {
        System.out.println("Error: decrypt mode requires an input file");
        System.out.println("       specify an input file by using \' -i [FILENAME] \' as an argument");
        System.exit(1);
      }
      //get key from file, build it, use it
      String keyString = new String(Files.readAllBytes(Paths.get(KEY_FILE_NAME)));
      byte[] keyEncoded = keyString.getBytes("UTF8");
      SecretKeySpec spec = new SecretKeySpec(keyEncoded, ALGORITHM);
      SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);

      SecretKey key = skf.generateSecret(spec);
      encryptor.setKey(key);
      output = encryptor.decrypt(input);
      System.out.println(output + "reached this point. figure out what to do");

    } else { //encrypt mode
      File keyFile = new File(KEY_FILE_NAME);
      if(!keyFile.exists()){
        System.out.println("No key file found. A new key was generated.");
        //get the key from the encryptor, write the bytes to a file
        FileWriter writer = new FileWriter(keyFile, false);
        //writes the new key to a file with the right name
        writer.write(Base64.encodeBase64String(encryptor.getKey().getEncoded()));
        writer.flush();
        writer.close();
      } else {
        //get the key bytes from the key.txt file, make the key then set the key of the encryptor Object.
        String keyString = new String(Files.readAllBytes(Paths.get(KEY_FILE_NAME)));
        byte[] keyEncoded = keyString.getBytes("UTF8");
        // AESKeySpec spec = new AESKeySpec(keyEncoded);
        SecretKeySpec spec = new SecretKeySpec(keyEncoded, ALGORITHM);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey key =  skf.generateSecret(spec);
        encryptor.setKey(key);

      }
      //ENCRYPT THAT SHIT NIGGA!!!
      output = encryptor.encrypt("encryptThatYo!!!");
      System.out.println("output: " + output);
    }

    //show the user the ecrypted text

    //give the user the option to either decrypt their text now, or to return to the application later to decrypt it (exiting it)

  }

}
