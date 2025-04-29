package seguridad;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;

public class BenchmarkVelocidad {
    public static void main(String[] args) throws Exception {
        // ------------------------------------------------------
        // 1) Preparar llaves
        // ------------------------------------------------------
        // 1a) AES: derivamos una llave de prueba (no importa el secreto real)
        SecretKeys keys = CriptoUtils.derivarLlaves(new byte[128]);
        
        // 1b) RSA: cargamos la llave pública desde disco
        byte[] pubEnc = Files.readAllBytes(Path.of("llaves/public.key"));
        PublicKey rsaPub = KeyFactory
            .getInstance("RSA")
            .generatePublic(new X509EncodedKeySpec(pubEnc));

        // ------------------------------------------------------
        // 2) Cifrado simétrico (AES-256-CBC)
        // ------------------------------------------------------
        final int N = 10_000;
        byte[] bloqueSim = new byte[16];                        // 16 bytes de datos
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        
        long t0 = System.nanoTime();
        for (int i = 0; i < N; i++) {
            byte[] iv = CriptoUtils.generarIV();
            aes.init(Cipher.ENCRYPT_MODE, 
                     new javax.crypto.spec.SecretKeySpec(keys.keyEnc, "AES"),
                     new IvParameterSpec(iv));
            aes.doFinal(bloqueSim);
        }
        long t1 = System.nanoTime();
        long totalSim = t1 - t0;
        double perSim = (double) totalSim / N;
        double opsSim = 1e9 / perSim;

        // ------------------------------------------------------
        // 3) Cifrado asimétrico (RSA-1024)
        // ------------------------------------------------------
        final int M = 1_000;
        byte[] bloqueAsim = "127.0.0.1:9001".getBytes();         // dato de ejemplo
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        
        long t2 = System.nanoTime();
        for (int i = 0; i < M; i++) {
            rsa.init(Cipher.ENCRYPT_MODE, rsaPub);
            rsa.doFinal(bloqueAsim);
        }
        long t3 = System.nanoTime();
        long totalAsim = t3 - t2;
        double perAsim = (double) totalAsim / M;
        double opsAsim = 1e9 / perAsim;

        // ------------------------------------------------------
        // 4) Mostrar resultados
        // ------------------------------------------------------
        System.out.println("===== Benchmark de cifrado =====");
        System.out.printf("AES-256-CBC:  iteraciones = %,d%n", N);
        System.out.printf("  Tiempo total = %,d ns%n", totalSim);
        System.out.printf("  Tiempo por op = %.2f ns%n", perSim);
        System.out.printf("  Ops por segundo = %.0f%n%n", opsSim);

        System.out.printf("RSA-1024:     iteraciones = %,d%n", M);
        System.out.printf("  Tiempo total = %,d ns%n", totalAsim);
        System.out.printf("  Tiempo por op = %.2f ns%n", perAsim);
        System.out.printf("  Ops por segundo = %.0f%n", opsAsim);
    }
}
