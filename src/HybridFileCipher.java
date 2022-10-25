/*
Usando a biblioteca JCA, realize em Java uma aplicação para cifrar ficheiros com um esquema híbrido,
ou seja, usando cifra simétrica e assimétrica. O conteúdo do ficheiro é cifrado com uma chave simétrica, a
qual é cifrada com a chave pública do destinatário do ficheiro. A aplicação recebe na linha de comandos
a opção para cifrar (-enc) ou decifrar (-dec) e o ficheiro para cifrar/decifrar.
No modo para cifrar, a aplicação também recebe o certificado com a chave pública do destinatário e
produz dois ficheiros, um com o conteúdo original cifrado e outro com a chave simétrica cifrada. Ambos
os ficheiros devem ser codificados em Base64. Valorizam-se soluções que validem o certificado antes de ser
usada a chave pública e que não imponham limites à dimensão do ficheiro a cifrar/decifrar.
No modo para decifrar, a aplicação recebe também i) ficheiro com conteúdo original cifrado; ii) ficheiro
com chave simétrica cifrada; iii) keystore com a chave privada do destinatário; e produz um novo ficheiro
com o conteúdo original decifrado.
Para a codificação e descodificação em stream de bytes em Base64 deve usar a biblioteca Apache Commons
Codec [1].
Considere os ficheiros .cer e .pfx em anexo ao enunciado onde estão chaves públicas e privadas necessárias
para testar a aplicação.
 */

import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;

import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Scanner;


public class HybridFileCipher {

    private static final int BUFFER_SIZE = 1024;
    private static String CERTIFICATE_FOLDER;

    public static void main(String[] args){

        Scanner scanner = new Scanner(System.in);
        String[] option;

        pickOptionMessage();

        while (true){

            try{

                option = scanner.nextLine().split(" ");
                switch (option[0]) {
                    case "-exit":
                        System.out.println("Closing ...");
                        System.exit(1);
                    case "-enc":

                        System.out.println("\n Encoding requires a path folder to verify the certificate! \n"
                        + "Folder Path: ");
                        CERTIFICATE_FOLDER = scanner.nextLine();

                        HybridCipher(option[1], option[2]);
                        break;
                    case "-dec":
                        HybridDecipher(option[1], option[2], getPrivateKey(option[3]));
                    default:
                        pickOptionMessage();
                        break;
                }
            } catch (Exception e) {
                System.out.println("Something went wrong! (" + e.fillInStackTrace() + ").");
            }
        }

    }

    private static void HybridCipher(String fileToEncode, String certificateName) throws Exception {

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey secretKey = keyGenerator.generateKey();

        Cipher cipherEncoder = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipherEncoder.init(Cipher.ENCRYPT_MODE, secretKey);

        FileOutputStream encodedFIS = new FileOutputStream("src/CipheredMsg.txt");

        writeToFile(cipherEncoder, fileToEncode, "src/CipheredMsg.txt");

        if (!verifyCertificate(certificateName)) throw new Exception("This Certificate is not Valid");

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Certificate certificate = factory.generateCertificate(new FileInputStream(certificateName));

        PublicKey publicKey = certificate.getPublicKey();

        Cipher cipherAsymmetric = Cipher.getInstance("RSA");
        cipherAsymmetric.init(Cipher.WRAP_MODE, publicKey);

        byte [] cipheredKeyBytes = cipherAsymmetric.wrap(secretKey);
        FileOutputStream cipheredKeyFIS = new FileOutputStream("src/CipheredSecretKey.txt");
        Base64OutputStream cipheredKeyBIS = new Base64OutputStream(cipheredKeyFIS);

        cipheredKeyBIS.write(cipheredKeyBytes);

        encodedFIS.close();
        cipheredKeyBIS.close();
        cipheredKeyFIS.close();

        System.out.println("File successfully encoded");
    }

    private static void HybridDecipher(String cipheredText, String keyFile, Key privateKey) throws Exception {

        //Cipher Setup for unwrap using the given Private Key
        Cipher decipherKey = Cipher.getInstance("RSA");
        decipherKey.init(Cipher.UNWRAP_MODE, privateKey);

        //Ciphered Secret Key
        FileInputStream keyFis = new FileInputStream(keyFile);
        Base64InputStream keyBIS = new Base64InputStream(keyFis);

        //Unwrapping the secret Key
        byte [] wrappedKey = keyBIS.readAllBytes();
        Key secretKey = decipherKey.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);

        //New decipher to be used to obtain the ciphered message
        Cipher decipherMsg = Cipher.getInstance("AES/ECB/PKCS5Padding");
        decipherMsg.init(Cipher.DECRYPT_MODE, secretKey);

        //Outputting the message to a file
        writeToFile(decipherMsg, cipheredText, "src/DecipheredMsg.txt");

        keyBIS.close();
        keyFis.close();

        System.out.println("File successfully decoded");
        pickOptionMessage();
    }

    private static Key getPrivateKey(String pfxFile) throws Exception{

        KeyStore ks = KeyStore.getInstance("PKCS12");
        char [] passwordArray = "changeit".toCharArray();

        ks.load(
                new FileInputStream(pfxFile),
                passwordArray
        );

        Enumeration<String> entries = ks.aliases();

        if(entries.hasMoreElements())
            return ks.getKey(entries.nextElement(), passwordArray);

        throw new Exception("No Private Key present in the given Certificate");
    }

    private static void pickOptionMessage(){
        System.out.println(
                """
                        Welcome!\s
                        Select one of the following options:\s
                        -enc {file-to-encode} {certificate-with-public-key}\s
                        -dec {file-to-decode} {secret-key-wrapped} {pfx-with-private-key}\s
                        -exit Exits.
                        """
        );
    }

    private static void writeToFile(Cipher cipher, String text, String output) throws Exception {
        FileInputStream inputFis = new FileInputStream(text);
        FileOutputStream outputFIS = new FileOutputStream(output);
        Base64OutputStream outputBIS = new Base64OutputStream(outputFIS);

        int read;
        byte[] buffer = new byte[BUFFER_SIZE];

        while((read = inputFis.read(buffer)) != -1){
            byte[] data = cipher.update(buffer, 0, read);
            outputBIS.write(data);
        }

        byte [] end = cipher.doFinal();
        outputBIS.write(end);
        outputBIS.flush();
        outputBIS.close();
        outputFIS.close();
        inputFis.close();
    }

    private static boolean verifyCertificate(String certificate) throws Exception {

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(certificate);
        X509Certificate cert = (X509Certificate) factory.generateCertificate(fis);

        // Creating the Issuer Certificate name so that we can look up for it in the folder passed by the User
        var issuer_name = cert.getIssuerDN().getName().split(",")[0].split("=")[1] + ".cer";

        // Getting the Directory with all the Certificate Files inside
        File dir = new File(CERTIFICATE_FOLDER);
        File[] files = dir.listFiles();

        // Iterating over all the Files till we found the correct certificate file
        for (int i = 0; i < (files != null ? files.length : 0); i++) {

            // In case we find the IC
            String s = files[i].getName();
            if (s.equals(issuer_name)) {

                // If the Path for the IC is the same as the Certificate Path itself, then we have reached a Trust Anchor
                if (files[i].getAbsolutePath().equals(certificate)) return true;

                // Else, we get the IC, and using its Public Key we validate our own Certificate
                FileInputStream ver = new FileInputStream(files[i].getAbsolutePath());
                X509Certificate cert_ver = (X509Certificate) factory.generateCertificate(ver);
                cert.verify(cert_ver.getPublicKey());

                // After that, we proceed to validate the IC using recursion
                return verifyCertificate(files[i].getAbsolutePath());
            }
        }

        // If we don't return inside the for we can assure there's nothing inside the folder that validates the certificate given
        return false;

    }
}
