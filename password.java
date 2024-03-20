package password;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class password {
    private static final String FILE_NAME = "passwords.dat";

    public static void main(String[] args) throws InvalidParameterSpecException, InvalidAlgorithmParameterException {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter master password: ");
        String masterPassword = scanner.nextLine();
        byte[] masterKey = getHash(masterPassword);

        Map<String, String> passwords = loadPasswords(masterKey);

        while (true) {
            System.out.println("\n1. Store Password");
            System.out.println("2. Retrieve Password");
            System.out.println("3. Exit");
            System.out.print("Enter your choice: ");
            String choice = scanner.nextLine();

            switch (choice) {
                case "1":
                    addPassword(scanner, passwords);
                    break;
                case "2":
                    retrievePassword(scanner, passwords);
                    break;
                case "3":
                    System.out.println("Exiting...");
                    savePasswords(passwords, masterKey);
                    System.exit(0);
                    break;
                default:
                    System.out.println("Invalid choice. Please try again.");
            }
        }
    }

    private static byte[] getHash(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(password.getBytes());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(1);
        }
        return null;
    }

    private static Map<String, String> loadPasswords(byte[] masterKey) {
        Map<String, String> passwords = new HashMap<>();
        try {
            File file = new File(FILE_NAME);
            if (file.exists() && !file.isDirectory()) {
                FileInputStream fis = new FileInputStream(FILE_NAME);
                ObjectInputStream ois = new ObjectInputStream(fis);
                byte[] iv = (byte[]) ois.readObject();
                byte[] encryptedPasswords = (byte[]) ois.readObject();
                ois.close();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                SecretKeySpec secretKeySpec = new SecretKeySpec(masterKey, "AES");
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
                byte[] decryptedPasswords = cipher.doFinal(encryptedPasswords);
                ObjectInputStream ois2 = new ObjectInputStream(new ByteArrayInputStream(decryptedPasswords));
                passwords = (Map<String, String>) ois2.readObject();
                ois2.close();
            }
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Error loading passwords: " + e.getMessage());
        }
        return passwords;
    }

    private static void savePasswords(Map<String, String> passwords, byte[] masterKey) throws InvalidParameterSpecException, InvalidAlgorithmParameterException {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(masterKey, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            AlgorithmParameters params = cipher.getParameters();
            byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(passwords);
            objectOutputStream.flush();
            objectOutputStream.close();
            byte[] encryptedPasswords = cipher.doFinal(byteArrayOutputStream.toByteArray());
            FileOutputStream fileOutputStream = new FileOutputStream(FILE_NAME);
            ObjectOutputStream objectOutputStream2 = new ObjectOutputStream(fileOutputStream);
            objectOutputStream2.writeObject(iv);
            objectOutputStream2.writeObject(encryptedPasswords);
            objectOutputStream2.close();
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Error saving passwords: " + e.getMessage());
        }
    }

    private static void addPassword(Scanner scanner, Map<String, String> passwords) {
        System.out.print("Enter account name: ");
        String account = scanner.nextLine();
        System.out.print("Enter password: ");
        String password = scanner.nextLine();
        passwords.put(account, password);
        System.out.println("Password stored successfully!");
    }

    private static void retrievePassword(Scanner scanner, Map<String, String> passwords) {
        System.out.print("Enter account name: ");
        String account = scanner.nextLine();
        if (passwords.containsKey(account)) {
            System.out.println("Password for " + account + ": " + passwords.get(account));
        } else {
            System.out.println("Password not found.");
        }
    }
}
