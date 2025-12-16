import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Program to generate and save a secret key (AES)
 * Usage: java KeyHandler <key-file-name>
 */
public class KeyHandler {
    /**
     * Main method to handle key file creation
     * @param args Command-line argument for the file name
     * @exception NoSuchAlgorithmException If the AES algorithm is not available
     */
    public static void main(String[] args) {
        // Check for no arguments or blank argument
        if (args.length != 1 || args[0].isBlank()) {
            System.out.println("Error: Expected 1 argument.");
            System.out.println("Usage: java KeyHandler <key-file-name>");
            System.exit(1);
        }

        String fileName = args[0];

        // Check if file already exists
        if(new File(fileName).exists()) {
            System.out.println("Error: File '" + fileName + "' already exists.");
            System.exit(1);
        }

        try {
            createKeyFile(fileName); // Call method to create key file
            System.out.println("Key file '" + fileName + "' has been successfully created.");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * Method to create a key file with a generated AES secret key
     * @param fileName Name of the file to save the key
     * @throws NoSuchAlgorithmException If the AES algorithm is not available
     */
    private static void createKeyFile(String fileName) throws NoSuchAlgorithmException {
        // AES key generation with 256 bits key size
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();

        // Write the secret key to the file
        try(ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(fileName))) {
            oos.writeObject(secretKey);
        } catch (IOException e) {
            e.printStackTrace();
        }    
    }
}
