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


import javax.crypto.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class HybridFileCipher {
    /*
    arg[0] - modo
    arg[1] - ficheiro
    arg[2] - cert
     */
    public static void main(String[] args)
            throws
            NoSuchAlgorithmException,
            NoSuchPaddingException,
            InvalidKeyException,
            IOException,
            IllegalBlockSizeException,
            BadPaddingException, KeyStoreException, CertificateException {
        File file = new File(args[1]);
        if(args[0].compareTo("enc") == 0){
            File [] files = HybridCipher(file, args[2]);
        }
    }

    private static File[] HybridCipher(File fileToCipher, String certificateName) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, KeyStoreException, IllegalBlockSizeException, BadPaddingException, IOException, CertificateException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey secretKey = keyGenerator.generateKey();

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte [] cipheredFileBytes = cipher.doFinal(Files.readAllBytes(fileToCipher.toPath()));
        File cipheredFile = new File("src/CipheredFile.txt");
        Files.write(Path.of(cipheredFile.getPath()), cipheredFileBytes);

        //Cipher Key using public key in certificate
        File certificateFile = new File(certificateName);

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Certificate certificate = factory.generateCertificate(new FileInputStream(certificateFile));

        PublicKey publicKey = certificate.getPublicKey();

        Cipher cipherAsymmetric = Cipher.getInstance("RSA");
        cipherAsymmetric.init(Cipher.WRAP_MODE, publicKey);

        byte [] cipheredKeyBytes = cipherAsymmetric.wrap(secretKey);
        File cipheredKey = new File("src/CipheredKeyBytes.txt");
        Files.write(Path.of(cipheredKey.getPath()), cipheredKeyBytes);

        return new File[]{};
    }
}
