// src/seguridad/Cliente.java
package seguridad;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

public class Cliente {
    private static final String HOST = "localhost";
    private static final int PUERTO = 8000;
    private static final Random RANDOM = new Random();

    public static void main(String[] args) {
        try {
            // 1) Parámetros DH de 1024 bits
            DHParameterSpec dhSpecTest = CriptoUtils.generarParametrosDH();
            System.out.println("DH p bit length = " + dhSpecTest.getP().bitLength());
            System.out.println("DH g bit length = " + dhSpecTest.getG().bitLength());

            // 2) Política de fuerza para AES-256
            int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
            System.out.println("Max AES key length supported = " + maxKeyLen);

            // 3) Clave derivada de ejemplo
            byte[] dummySecret = new byte[128];
            SecretKeys testKeys = CriptoUtils.derivarLlaves(dummySecret);
            System.out.println("Longitud de keyEnc en bits = " + (testKeys.keyEnc.length * 8));

            try (Scanner sc = new Scanner(System.in)) {
                System.out.println("Seleccione modo:");
                System.out.println("1) Interactivo");
                System.out.println("2) Prueba de carga");
                System.out.print("Opción: ");
                int opcion = sc.nextInt();
                if (opcion == 1) {
                    modoInteractivo(sc);
                } else if (opcion == 2) {
                    modoPruebaCarga(sc);
                } else {
                    System.out.println("Opción inválida");
                }
            }
        } catch (Exception e) {
            System.err.println("Error en la consulta");
        }
    }

    private static void modoInteractivo(Scanner sc) {
        try {
            Solicitud req = new Solicitud();
            if (!req.handshakeYRecibirTabla()) return;
            System.out.println("Servicios:\n" + req.tablaTexto);
            System.out.print("Ingrese ID de servicio: ");
            req.elegido = sc.nextInt();
            req.enviarYMostrarRespuesta();
        } catch (Exception e) {
            System.err.println("Error en la consulta");
        }
    }

    private static void modoPruebaCarga(Scanner sc) {
        System.out.print("Cantidad de instancias: ");
        int n = sc.nextInt();
        System.out.print("Tipo Secuencial (S) o Concurrente (C): ");
        String tipo = sc.next();
        if (tipo.equalsIgnoreCase("S")) {
            for (int i = 0; i < n; i++) {
                try {
                    Solicitud req = new Solicitud();
                    if (!req.handshakeYRecibirTabla()) continue;
                    req.elegido = req.ids.get(RANDOM.nextInt(req.ids.size()));
                    req.enviarYMostrarRespuesta();
                } catch (Exception e) {
                    System.err.println("Error en la consulta");
                }
            }
        } else {
            ExecutorService pool = Executors.newFixedThreadPool(Math.min(n, 100));
            for (int i = 0; i < n; i++) {
                pool.submit(() -> {
                    try {
                        Solicitud req = new Solicitud();
                        if (!req.handshakeYRecibirTabla()) return;
                        req.elegido = req.ids.get(RANDOM.nextInt(req.ids.size()));
                        req.enviarYMostrarRespuesta();
                    } catch (Exception e) {
                        System.err.println("Error en la consulta");
                    }
                });
            }
            pool.shutdown();
            try {
                pool.awaitTermination(1, TimeUnit.HOURS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static class Solicitud {
        Socket socket;
        DataInputStream in;
        DataOutputStream out;
        SecretKeys keys;
        List<Integer> ids;
        String tablaTexto;
        int elegido;

        Solicitud() throws IOException {
            socket = new Socket(HOST, PUERTO);
            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());
        }

        boolean handshakeYRecibirTabla() {
            try {
                byte[] pub = Files.readAllBytes(Path.of("llaves/public.key"));
                PublicKey rsaPub = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(pub));
                
                System.out.println("[Cliente] Leyendo parámetros DH y firma del servidor");
                int lp = in.readInt(); byte[] pB = new byte[lp]; in.readFully(pB);
                int lg = in.readInt(); byte[] gB = new byte[lg]; in.readFully(gB);
                int ly = in.readInt(); byte[] ySB = new byte[ly]; in.readFully(ySB);
                int lf = in.readInt(); byte[] sig = new byte[lf]; in.readFully(sig);
                
                System.out.printf("[Cliente] Recibido p(%d), g(%d), yS(%d), firma(%d)%n",
                          lp, lg, ly, lf);

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write(pB); baos.write(gB); baos.write(ySB);
                if (!CriptoUtils.verificarRSA(rsaPub, baos.toByteArray(), sig)) {
                    System.err.println("Error en la consulta");
                    cerrar();
                    return false;
                }
                System.out.println("[Cliente] Firma verificada con éxito\n");

                
                BigInteger p = new BigInteger(pB), g = new BigInteger(gB);
                DHParameterSpec dhSpec = new DHParameterSpec(p, g);
                KeyPair kpC = CriptoUtils.generarClavesDH(dhSpec);
                byte[] yC = ((DHPublicKey)kpC.getPublic()).getY().toByteArray();
                System.out.printf("[Cliente] Enviando clave pública DH yC (%d bytes)%n", yC.length);

                out.writeInt(yC.length); out.write(yC);

                System.out.println("[Cliente] Derivando llaves de sesión");

                DHPublicKeySpec specS = new DHPublicKeySpec(new BigInteger(ySB), p, g);
                PublicKey pubS = KeyFactory.getInstance("DH").generatePublic(specS);
                KeyAgreement ka = KeyAgreement.getInstance("DH");
                ka.init(kpC.getPrivate()); ka.doPhase(pubS, true);
                keys = CriptoUtils.derivarLlaves(ka.generateSecret());

                System.out.println("[Cliente] Leyendo IV, ciphertext y HMAC de la tabla");

                int iv1l = in.readInt(); byte[] iv1 = new byte[iv1l]; in.readFully(iv1);
                int ct1l = in.readInt(); byte[] ct1 = new byte[ct1l]; in.readFully(ct1);
                int hm1l = in.readInt(); byte[] hm1 = new byte[hm1l]; in.readFully(hm1);
                
                System.out.printf("[Cliente] Recibido IV1(%d), CT1(%d), HMAC1(%d)%n\n", iv1l, ct1l, hm1l);


                if (!CriptoUtils.verificarHMAC(keys.keyHmac, ct1, hm1)) {
                    System.err.println("Error en la consulta");
                    cerrar();
                    return false;
                }
                tablaTexto = new String(CriptoUtils.descifrarAES(keys.keyEnc, iv1, ct1));
                
                ids = new ArrayList<>();
                for (String linea : tablaTexto.split("\n")) {
                    if (linea.contains(";")) {
                        String[] parts = linea.split(";",2);
                        if (parts[0].trim().matches("\\d+"))
                            ids.add(Integer.parseInt(parts[0].trim()));
                    }
                }
                return true;
            } catch (Exception e) {
                System.err.println("Error en la consulta");
                try { cerrar(); } catch (IOException ignored) {}
                return false;
            }
        }

        void enviarYMostrarRespuesta() {
            try {
                byte[] iv2 = CriptoUtils.generarIV();
                byte[] ct2 = CriptoUtils.cifrarAES(keys.keyEnc, iv2, String.valueOf(elegido).getBytes());
                byte[] hm2 = CriptoUtils.calcularHMAC(keys.keyHmac, ct2);
                out.writeInt(iv2.length); out.write(iv2);
                out.writeInt(ct2.length); out.write(ct2);
                out.writeInt(hm2.length); out.write(hm2);

                int iv3l = in.readInt(); byte[] iv3 = new byte[iv3l]; in.readFully(iv3);
                int ct3l = in.readInt(); byte[] ct3 = new byte[ct3l]; in.readFully(ct3);
                int hm3l = in.readInt(); byte[] hm3 = new byte[hm3l]; in.readFully(hm3);
                if (!CriptoUtils.verificarHMAC(keys.keyHmac, ct3, hm3)) {
                    System.err.println("Error en la consulta");
                } else {
                    String resp = new String(CriptoUtils.descifrarAES(keys.keyEnc, iv3, ct3));
                    System.out.println("Servicios:\n" + tablaTexto);
                    System.out.println("Servicio elegido: " + elegido);
                    System.out.println("Servidor responde: " + resp);
                }
            } catch (Exception e) {
                System.err.println("Error en la consulta");
            } finally {
                try { cerrar(); } catch (IOException ignored) {}
            }
        }

        private void cerrar() throws IOException {
            in.close(); out.close(); socket.close();
        }
    }
}
