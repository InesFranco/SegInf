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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Enumeration;
import java.util.Scanner;


public class HybridFileCipher {

    private static final int BUFFER_SIZE = 1024;

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
                        HybridCipher(option[1], option[2]);
                        break;
                    case "-dec":
                        HybridDecipher(option[1], option[2], getPrivateKey(option[3]));
                    default:
                        pickOptionMessage();
                        break;
                }
            } catch (Exception ignored) {
                System.out.println("Something went wrong!");
            }
        }

    }

    private static void HybridCipher(String fileToEncode, String certificateName) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, CertificateException {

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey secretKey = keyGenerator.generateKey();

        Cipher cipherEncoder = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipherEncoder.init(Cipher.ENCRYPT_MODE, secretKey);

        FileOutputStream encodedFIS = new FileOutputStream("src/CipheredFile.txt");

        writeToFile(cipherEncoder, fileToEncode, "src/CipheredFile.txt");

        //TODO() - VALIDATE CERTIFICATE HERE

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Certificate certificate = factory.generateCertificate(new FileInputStream(certificateName));

        PublicKey publicKey = certificate.getPublicKey();

        Cipher cipherAsymmetric = Cipher.getInstance("RSA");
        cipherAsymmetric.init(Cipher.WRAP_MODE, publicKey);

        byte [] cipheredKeyBytes = cipherAsymmetric.wrap(secretKey);
        FileOutputStream cipheredKeyFIS = new FileOutputStream("src/CipheredKeyBytes.txt");
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
        SecretKey secretKey = (SecretKey) decipherKey.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);

        //New decipher to be used to obtain the ciphered message
        Cipher decipherMsg = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decipherMsg.init(Cipher.DECRYPT_MODE, secretKey);

        //Output for the message after deciphered
        writeToFile(decipherMsg, cipheredText, "src/DecipheredText.txt");

        keyBIS.close();
        keyFis.close();

        System.out.println("File successfully decoded");
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

    private static void writeToFile(Cipher cipher, String text, String output) throws IOException, IllegalBlockSizeException, BadPaddingException {
        FileInputStream inputFis = new FileInputStream(text);
        FileOutputStream outputFIS = new FileOutputStream(output);
        Base64OutputStream outputBIS = new Base64OutputStream(outputFIS);

        int read;
        byte[] buffer = new byte[BUFFER_SIZE];

        while((read = inputFis.read(buffer)) != -1){
            byte[] data = cipher.update(buffer, 0, read);
            outputBIS.write(data);
        }

        outputBIS.write(cipher.doFinal());
        outputBIS.flush();
        outputBIS.close();
        outputFIS.close();
        inputFis.close();
    }
}
