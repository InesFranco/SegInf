import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;

public class ClientAPP {
    public static void main(String[] args) throws Exception {
        try {
            SSLSocketFactory sslFactory =
                    HttpsURLConnection.getDefaultSSLSocketFactory();
            SSLSocket socket =
                    (SSLSocket) sslFactory.createSocket("www.server-secure.edu", 4433);

            socket.startHandshake();

            PrintWriter out = new PrintWriter(
                    new BufferedWriter(
                            new OutputStreamWriter(
                                    socket.getOutputStream())));

            //request
            out.println("GET / HTTP/1.0");
            out.println();
            out.flush(); //enviar o conteudo no buffer

            if (out.checkError())
                System.out.println("SSLSocketClient:  java.io.PrintWriter error");


            BufferedReader in = new BufferedReader( //response
                    new InputStreamReader(
                            socket.getInputStream()));

            String inputLine;
            while ((inputLine = in.readLine()) != null)
                System.out.println(inputLine);

            in.close();
            out.close();
            socket.close();

        } catch (Exception e){
            e.printStackTrace();
        }
    }
}
