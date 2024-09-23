import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class password {
    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        boolean createdFile = createPasswordFile();
        String fileName = "Password Manager.txt";

        BufferedReader passReadFile= new BufferedReader(new FileReader(fileName));
        Scanner scanner = new Scanner(System.in);

        if (createdFile){ //create a passcode for this new file
            FileWriter passWriteFile = new FileWriter(fileName);
            System.out.println("Please enter a passcode for your new password manager");
            String newPasscode = scanner.nextLine();

            createPasscode(newPasscode, passWriteFile); // creates salt and encrypted passcode
            passWriteFile.close();
        }
        else {
            System.out.println("Please enter your passcode");
            String inputPasscode = scanner.nextLine(); //this becomes the key for encryption and decryption

            String line;
            line = passReadFile.readLine();
            String[] saltEncrypt = line.split(":", 2); //the first line is always the salt:encrypted_password
            String saltEnc = saltEncrypt[0];
            String passEncrypt = saltEncrypt[1];

            byte[] salt = Base64.getDecoder().decode(saltEnc); //obtains the decoded salt

            String encryptedPasscode = myEncrypt(inputPasscode, inputPasscode, salt);

            Map<String, String> passwordMap = new HashMap<>(); // contains all passwords associated with their label
            passwordMap = savePasswords(passReadFile, passwordMap); // saves all current passwords in text file into a hash map

            //System.out.println(passEncrypt.equals(inputPasscode));
            if(passEncrypt.equals(encryptedPasscode)){
                System.out.println("Would you like to add a password, read a password, or quit?");
                System.out.println("a, r, or q are valid inputs");
                String task = scanner.nextLine();
                if (task.equals("a")){
                    //add a password
                    System.out.println("Enter label for password: ");
                    String label = scanner.nextLine();
                    System.out.println("Enter password to store");
                    String password = scanner.nextLine();
                    String newPassEncr = myEncrypt(password, inputPasscode, salt);
                    passwordMap.put(label, newPassEncr);

                    FileWriter passWriteFile = new FileWriter(fileName);
                    passWriteFile.write(saltEnc + ":" + passEncrypt + "\n");
                    writePassFile(passwordMap, passWriteFile);

                    passWriteFile.close();

                }
                else if (task.equals("r")){
                    //read a password
                    System.out.println("Enter label for password you want to find: ");
                    String label = scanner.nextLine();
                    String password = myDecrypt(passwordMap.get(label), inputPasscode, salt);
                    System.out.println(password);
                }
                else if (task.equals("q")){
                    System.out.println("quitting");
                    System.exit(1);
                }
                else {
                    System.out.println("Invalid input, quitting");
                    System.exit(1);
                }

            }
            else {
                System.out.println("Passcode is wrong. Exiting");
                System.exit(1);
            }
        }

    }

    private static void writePassFile(Map<String, String> passwordMap, FileWriter passWriteFile) throws IOException {
        for (Map.Entry<String, String> entry : passwordMap.entrySet()) {
            passWriteFile.write(entry.getKey() + ":" + entry.getValue() + "\n");
            //System.out.println("Key: " + entry.getKey() + ", Value: " + entry.getValue());
        }
    }

    private static String myDecrypt(String message, String stringKey, byte[] salt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {

        byte[] decoded;
        KeySpec spec = new PBEKeySpec(stringKey.toCharArray(), salt, 600000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey sharedKey = factory.generateSecret(spec);
        byte[] encoded = sharedKey.getEncoded();
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(encoded, "AES");

        cipher.init(Cipher.DECRYPT_MODE, key);
        decoded = Base64.getDecoder().decode(message);
        byte[] decrypted = cipher.doFinal(decoded);

        return new String(decrypted);
    }

    private static String myEncrypt(String message, String stringKey, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        byte[] decoded;
        KeySpec spec = new PBEKeySpec(stringKey.toCharArray(), salt, 600000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey sharedKey = factory.generateSecret(spec);
        byte[] encoded = sharedKey.getEncoded();
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(encoded, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, key);
        decoded = cipher.doFinal(message.getBytes());

        return new String(Base64.getEncoder().encode(decoded));
    }

    private static Map<String, String> savePasswords(BufferedReader passReadFile, Map<String, String> passwordMap) throws IOException {
        String line;
        while ((line = passReadFile.readLine()) != null) {
            String[] parts = line.split(":", 2); // Split at the first colon
            if (parts.length == 2) {
                String key = parts[0].trim();
                String value = parts[1].trim();
                passwordMap.put(key, value);
            }
        }
        return passwordMap;

    }

    private static void createPasscode(String passcode, FileWriter file) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        String saltString = Base64.getEncoder().encodeToString(salt);

        String encryptedPassword = myEncrypt(passcode, passcode, salt);
        file.write(saltString + ":" + encryptedPassword);

    }

    private static boolean createPasswordFile() {
        try {
            File myObj = new File("Password Manager.txt");
            if (myObj.createNewFile()) {
                System.out.println("No password file detected, creating a new password file");
                System.out.println("File created: " + myObj.getName());
                return true;
            } else {
                return false;
            }
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
            return false;
        }
    }

    /*
    private static boolean enterPasscode(String passcode, BufferedReader file) throws IOException {
        String filePasscode = file.readLine();
        String enteredPasscode = "imAX339AfcRcrLzvq5wOVg==: " + passcode;

        return filePasscode.equals(enteredPasscode);
    }

     */
}
