import java.io.File;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Program to encrypt a file using AES
 * Usage: java EncryptHandler <data> <secretKey> <outputFile>
 */
public class EncryptHandler {
    /**
     * Main method to handle file encryption
     * @param args Command-line arguments for data file, secret key file, and output file
     * @exception Exception If an error occurs during encryption
     */
    public static void main(String[] args) {
        if(args.length != 3) {
            System.out.println("Error: Expected 3 arguments.");
            System.out.println("Usage: java EncryptHandler <data> <secretKey> <outputFile>");
            System.exit(1);
        }

        // Parse command-line arguments
        String data = args[0];
        String secretKey = args[1];
        String outputFile = args[2];
        
        // Check for blank arguments
        if (data.isBlank() || secretKey.isBlank() || outputFile.isBlank()) {
            System.out.println("Error: One or more arguments are blank.");
            System.out.println("Usage: java EncryptHandler <data> <secretKey> <outputFile>");
            System.exit(1);

        // Check if input files exist
        }else if(!new File(data).exists() || !new File(secretKey).exists()) { 
            System.out.println("Error: Data file or secret key file does not exist.");
            System.out.println("Usage: java EncryptHandler <data> <secretKey> <outputFile>");
            System.exit(1);

        // Check if output file already exists
        } else if (new File (outputFile).exists()) {
            System.out.println("Error: Output file '" + outputFile + "' already exists.");
            System.exit(1);
        }

        try {
            EncryptHandler handler = new EncryptHandler();
            handler.encryptFile(data, outputFile, secretKey); // Call method to encrypt file
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Method to encrypt a file using AES encryption
     * @param inputFile Name of the input data file
     * @param outputFile Name of the output encrypted file
     * @param keyFile Name of the secret key file
     * @throws Exception If an error occurs during encryption
     */
    private void encryptFile(String inputFile, String outputFile, String keyFile) throws Exception {
        // Read the secret key from the key file
        SecretKey secretKey;
        try (java.io.ObjectInputStream ois = new java.io.ObjectInputStream(new java.io.FileInputStream(keyFile))) {
            secretKey = (SecretKey) ois.readObject();
        }

        // Use AES encryption with CBC mode and PKCS5 padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        
        // Generate random 16 bytes IV
        byte[] iv = new byte[16]; 
        new java.security.SecureRandom().nextBytes(iv); 
        IvParameterSpec ivParams = new IvParameterSpec(iv);

        // Initialize cipher for encryption
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);

        // Read input file and encrypt data
        byte[] inputBytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(inputFile));
        byte[] outputBytes = cipher.doFinal(inputBytes);
        
        // Combine IV and encrypted data
        byte[] combined = new byte[iv.length + outputBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(outputBytes, 0, combined, iv.length, outputBytes.length);

        // Write the IV and encrypted data to the output file
        java.nio.file.Files.write(java.nio.file.Paths.get(outputFile), combined);

        System.out.println("Encryption completed. Encrypted data written to: " + outputFile);
    }
} 