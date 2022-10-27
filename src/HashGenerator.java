import java.io.File;

import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Scanner;

/**
 * Um dos Testes Realizados
 *
 * SHA1 CA1_int.cer
 * output -> 1b8d5ccf68b3bc642ae22bef68b94284acab66c3
 **/

public class HashGenerator {

    public static void main(String[] args) throws Exception {

        Scanner scanner = new Scanner(System.in);
        String[] input = null;

        while(input == null) {
            System.out.println(
                    """
                            Welcome!\s
                            Insert a hash function and the file you want to obtain the hash from:
                            """
            );

            input = scanner.nextLine().split(" ");
        }

        String hashName = input[0];
        StringBuilder filePath = new StringBuilder(input[1]);

        for (int i = 2; i < args.length; i++)
            filePath.append(" ").append(args[i]);


        File file = new File(filePath.toString());
        byte[] fileToByte = Files.readAllBytes(file.toPath());

        MessageDigest md = MessageDigest.getInstance(hashName);
        md.update(fileToByte);
        byte[] h = md.digest();
        prettyPrint(h);
    }

    private static void prettyPrint(byte[] tag) {
        for (byte b : tag) {
            System.out.printf("%02x", b);
        }
        System.out.println();

    }
}