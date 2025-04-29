package seguridad;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class MedidorVelocidadCifrado {
    private static final SecureRandom RNG = new SecureRandom();

    public static void main(String[] args) throws Exception {
        // 1) Parámetros del medidor: cuántas iteraciones se harán?
        final int ITERACIONES_AES = 10_000;
        final int ITERACIONES_RSA = 1_000;

        // 2) bloque de datos fijo de 16 bytes para AES
        byte[] datosAES = new byte[16];
        RNG.nextBytes(datosAES);

        // 3) Generar clave AES de 256 bits e IV de 16 bytes
        byte[] claveAES = new byte[32];
        RNG.nextBytes(claveAES);
        byte[] iv = CriptoUtils.generarIV();

        // 4) Cargar la llave pública RSA 
        byte[] pubBytes = Files.readAllBytes(Path.of("llaves/public.key"));
        PublicKey rsaPublica = KeyFactory.getInstance("RSA")
            .generatePublic(new X509EncodedKeySpec(pubBytes));

        // 5) bloque de datos (aprox 100 bytes) para el cifrado RSA
        byte[] datosRSA = new byte[100];
        RNG.nextBytes(datosRSA);

        // 6) Algunas cuantas operaciones antes de medir
        for (int i = 0; i < 100; i++) {
            CriptoUtils.cifrarAES(claveAES, iv, datosAES);
            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, rsaPublica);
            rsa.doFinal(datosRSA);
        }

        // 7) Medir AES
        long tInicio = System.nanoTime();
        for (int i = 0; i < ITERACIONES_AES; i++) {
            CriptoUtils.cifrarAES(claveAES, iv, datosAES);
        }
        long tFin = System.nanoTime();
        double nsPorOpAES = (tFin - tInicio) / (double) ITERACIONES_AES;
        double opsPorSegAES = 1e9 / nsPorOpAES;

        // 8) Medir RSA
        tInicio = System.nanoTime();
        for (int i = 0; i < ITERACIONES_RSA; i++) {
            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, rsaPublica);
            rsa.doFinal(datosRSA);
        }
        tFin = System.nanoTime();
        double nsPorOpRSA = (tFin - tInicio) / (double) ITERACIONES_RSA;
        double opsPorSegRSA = 1e9 / nsPorOpRSA;

        // 9) Mostrar resultados 
        System.out.println("--- Medidor de velocidad de cifrado ---");
        System.out.printf("%-15s %20s %20s%n", 
            "Algoritmo", "Tiempo medio (ns/op)", "Ops por segundo");
        System.out.printf("%-15s %20.2f %20.0f%n", 
            "AES-256-CBC", nsPorOpAES, opsPorSegAES);
        System.out.printf("%-15s %20.2f %20.0f%n", 
            "RSA-1024",    nsPorOpRSA, opsPorSegRSA);
    }
}
