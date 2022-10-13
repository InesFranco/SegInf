import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;



public class HashGenerator{
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        FileInputStream in = null;
        MessageDigest md = MessageDigest.getInstance("SHA-1");

        try {
            in = new FileInputStream("C:/Users/Ines/OneDrive - Instituto Superior de Engenharia de Lisboa/Desktop/Universidade/SegInf/SegInf/Enunciado/certificates-and-keys/cert-int/CA1-int.cer");
            byte msg;
            while ((msg = (byte) in.read()) != -1) {
                md.update(msg);
            }
            byte[] h = md.digest();
            prettyPrint(h);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }

    private static void prettyPrint(byte[] h) {
        for (byte b : h) {
            System.out.printf("%02x", b);
        }
        System.out.println();
    }
}
