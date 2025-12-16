import java.io.File;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Program to decrypt a file using AES
 * Usage: java DecryptHandler <encryptedData> <secretKey> <outputFile>
 */
public class DecryptHandler {
    /**
     * Main method to handle file decryption
     * @param args Command-line arguments for encrypted data file, secret key file, and output file
     * @exception Exception If an error occurs during decryption
     */
    public static void main(String[] args) {
        if(args.length != 3) {
            System.out.println("Error: Expected 3 arguments.");
            System.out.println("Usage: java DecryptHandler <encryptedData> <secretKey> <outputFile>");
            System.exit(1);
        }

        // Parse command-line arguments
        String encryptedData = args[0];
        String secretKey = args[1];
        String outputFile = args[2];
        
        // Check for blank arguments
        if (encryptedData.isBlank() || secretKey.isBlank() || outputFile.isBlank()) {
            System.out.println("Error: One or more arguments are blank.");
            System.out.println("Usage: java DecryptHandler <encryptedData> <secretKey> <outputFile>");
            System.exit(1);
        
        // Check if input files exist
        }else if(!new File(encryptedData).exists() || !new File(secretKey).exists()) {
            System.out.println("Error: The encrypted data or secret key file does not exist.");
            System.out.println("Usage: java DecryptHandler <encryptedData> <secretKey> <outputFile>");
            System.exit(1);
        
        // Check if output file already exists
        } else if (new File (outputFile).exists()) {
            System.out.println("Error: Output file '" + outputFile + "' already exists.");
            System.exit(1);
        }

        try {
            DecryptHandler handler = new DecryptHandler();
            handler.decryptFile(encryptedData, outputFile, secretKey); // Call method to decrypt file
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    /**
     * Method to decrypt a file using AES decryption
     * @param inputFile the file to be decrypted
     * @param outputFile the file to write the decrypted data
     * @param keyFile the secret key file
     * @throws Exception If an error occurs during decryption
     */
    private void decryptFile(String inputFile, String outputFile, String keyFile) throws Exception {
        // Read the secret key from the key file
        SecretKey secretKey;
        try (java.io.ObjectInputStream ois = new java.io.ObjectInputStream(new java.io.FileInputStream(keyFile))) {
            secretKey = (SecretKey) ois.readObject();
        }
        
        // Read the encrypted data from the input file
        byte[] fileBytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(inputFile));
        
        // Extract IV and encrypted data
        byte[] iv = java.util.Arrays.copyOfRange(fileBytes, 0, 16);
        byte[] encryptedBytes = java.util.Arrays.copyOfRange(fileBytes, 16, fileBytes.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);

        // Decrypt the data
        byte[] outputBytes = cipher.doFinal(encryptedBytes);

        // Write decrypted data to output file
        java.nio.file.Files.write(java.nio.file.Paths.get(outputFile), outputBytes);
        System.out.println("Decryption completed. Decrypted data written to: " + outputFile);
    }
}
