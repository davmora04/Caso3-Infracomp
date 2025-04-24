package seguridad;

import java.nio.file.*;
import java.security.*;

public class GeneradorLlaves {
    public static void main(String[] args) throws Exception {
        // Crear carpeta llaves si no existe
        Path dir = Paths.get("llaves");
        if (Files.notExists(dir)) {
            Files.createDirectories(dir);
            System.out.println("Directorio 'llaves' creado.");
        }

        // Generar par de llaves RSA
        KeyPair rsa = CriptoUtils.generarClavesRSA();
        // Escribir llave pública
        Files.write(dir.resolve("public.key"), rsa.getPublic().getEncoded());
        // Escribir llave privada
        Files.write(dir.resolve("private.key"), rsa.getPrivate().getEncoded());
        System.out.println("Llaves RSA generadas y guardadas en 'llaves/'");
    }
}
