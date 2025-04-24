package seguridad;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

public class Cliente {
    private static final String HOST = "localhost";
    private static final int PUERTO = 8000;

    public static void main(String[] args) throws Exception {
        // 1) Cargar llave pública RSA del servidor
        byte[] pub = Files.readAllBytes(Path.of("llaves/public.key"));
        PublicKey rsaPub = KeyFactory.getInstance("RSA")
            .generatePublic(new X509EncodedKeySpec(pub));

        try (Socket s = new Socket(HOST, PUERTO);
             DataInputStream in = new DataInputStream(s.getInputStream());
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {

            // 2) Recibir parámetros DH + firma
            int lp = in.readInt(); byte[] pB = new byte[lp]; in.readFully(pB);
            int lg = in.readInt(); byte[] gB = new byte[lg]; in.readFully(gB);
            int ly = in.readInt(); byte[] ySB = new byte[ly]; in.readFully(ySB);
            int lf = in.readInt(); byte[] sig = new byte[lf]; in.readFully(sig);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(pB); baos.write(gB); baos.write(ySB);
            if (!CriptoUtils.verificarRSA(rsaPub, baos.toByteArray(), sig)) {
                System.err.println("Firma inválida");
                return;
            }

            // 3) Generar pares DH y enviar Yc
            BigInteger p = new BigInteger(pB), g = new BigInteger(gB);
            DHParameterSpec dhSpec = new DHParameterSpec(p, g);
            KeyPair kpC = CriptoUtils.generarClavesDH(dhSpec);
            byte[] yC = ((DHPublicKey)kpC.getPublic()).getY().toByteArray();
            out.writeInt(yC.length); out.write(yC);

            // 4) Derivar llaves
            DHPublicKeySpec pubSpecS = new DHPublicKeySpec(new BigInteger(ySB), p, g);
            PublicKey pubS = KeyFactory.getInstance("DH").generatePublic(pubSpecS);
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(kpC.getPrivate()); ka.doPhase(pubS, true);
            SecretKeys keys = CriptoUtils.derivarLlaves(ka.generateSecret());

            // 5) Recibir tabla de servicios
            int iv1l = in.readInt(); byte[] iv1 = new byte[iv1l]; in.readFully(iv1);
            int ct1l = in.readInt(); byte[] ct1 = new byte[ct1l]; in.readFully(ct1);
            int hm1l = in.readInt(); byte[] hm1 = new byte[hm1l]; in.readFully(hm1);
            if (!CriptoUtils.verificarHMAC(keys.keyHmac, ct1, hm1)) {
                System.err.println("HMAC inválido");
                return;
            }
            String tabla = new String(CriptoUtils.descifrarAES(keys.keyEnc, iv1, ct1));
            System.out.println("Servicios:\n" + tabla);

            // 6) Elegir ID aleatorio (saltando el encabezado)
            List<Integer> ids = new ArrayList<>();
            for (String linea : tabla.split("\n")) {
                if (!linea.contains(";")) continue;
                String[] parts = linea.split(";", 2);
                if (parts[0].trim().matches("\\d+")) {
                    ids.add(Integer.parseInt(parts[0].trim()));
                }
            }
            int elegido = ids.get(new Random().nextInt(ids.size()));
            System.out.println("Servicio elegido: " + elegido);

            // 7) Enviar ID cifrado + HMAC
            byte[] iv2 = CriptoUtils.generarIV();
            byte[] ct2 = CriptoUtils.cifrarAES(keys.keyEnc, iv2, String.valueOf(elegido).getBytes());
            byte[] hm2 = CriptoUtils.calcularHMAC(keys.keyHmac, ct2);
            out.writeInt(iv2.length); out.write(iv2);
            out.writeInt(ct2.length); out.write(ct2);
            out.writeInt(hm2.length); out.write(hm2);

            // 8) Recibir respuesta IP:puerto
            int iv3l = in.readInt(); byte[] iv3 = new byte[iv3l]; in.readFully(iv3);
            int ct3l = in.readInt(); byte[] ct3 = new byte[ct3l]; in.readFully(ct3);
            int hm3l = in.readInt(); byte[] hm3 = new byte[hm3l]; in.readFully(hm3);
            if (!CriptoUtils.verificarHMAC(keys.keyHmac, ct3, hm3)) {
                System.err.println("HMAC respuesta inválido");
                return;
            }
            String resp = new String(CriptoUtils.descifrarAES(keys.keyEnc, iv3, ct3));
            System.out.println("Servidor responde: " + resp);
        }
    }
}
