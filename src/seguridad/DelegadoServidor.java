package seguridad;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.util.Map;

public class DelegadoServidor implements Runnable {
    private final Socket socket;
    private final PublicKey rsaPublic;
    private final PrivateKey rsaPrivate;
    private final Map<Integer, ServidorPrincipal.Servicio> tabla;

    public DelegadoServidor(Socket s,
                            PublicKey pub,
                            PrivateKey priv,
                            Map<Integer, ServidorPrincipal.Servicio> tabla) {
        this.socket = s;
        this.rsaPublic = pub;
        this.rsaPrivate = priv;
        this.tabla = tabla;
    }

    @Override
    public void run() {
        try (DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

            // 1) Handshake DH + firma RSA
            long tFirmaInicio = System.nanoTime();
            DHParameterSpec dhSpec = CriptoUtils.generarParametrosDH();
            KeyPair kpDH = CriptoUtils.generarClavesDH(dhSpec);
            byte[] pB   = dhSpec.getP().toByteArray();
            byte[] gB   = dhSpec.getG().toByteArray();
            byte[] ySB  = ((DHPublicKey)kpDH.getPublic()).getY().toByteArray();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(pB); baos.write(gB); baos.write(ySB);
            byte[] firma = CriptoUtils.firmarRSA(rsaPrivate, baos.toByteArray());
            long tFirma = System.nanoTime() - tFirmaInicio;

            out.writeInt(pB.length); out.write(pB);
            out.writeInt(gB.length); out.write(gB);
            out.writeInt(ySB.length); out.write(ySB);
            out.writeInt(firma.length); out.write(firma);

            // 2) Recibir clave pública DH cliente
            int lenYc = in.readInt();
            byte[] yC = new byte[lenYc];
            in.readFully(yC);
            DHPublicKeySpec keySpecC =
                new DHPublicKeySpec(new BigInteger(yC), dhSpec.getP(), dhSpec.getG());
            PublicKey pubC = KeyFactory.getInstance("DH").generatePublic(keySpecC);

            // 3) Derivar llaves de sesión
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(kpDH.getPrivate());
            ka.doPhase(pubC, true);
            SecretKeys keys = CriptoUtils.derivarLlaves(ka.generateSecret());

            // 4) Cifrar tabla + HMAC
            StringBuilder sb = new StringBuilder("ID;Servicio\n");
            for (ServidorPrincipal.Servicio s : tabla.values()) {
                sb.append(s.id).append(";").append(s.nombre).append("\n");
            }
            byte[] claroTabla = sb.toString().getBytes();

            long tCifTablaIni = System.nanoTime();
            byte[] iv1 = CriptoUtils.generarIV();
            byte[] ct1 = CriptoUtils.cifrarAES(keys.keyEnc, iv1, claroTabla);
            byte[] hm1 = CriptoUtils.calcularHMAC(keys.keyHmac, ct1);
            long tCifTabla = System.nanoTime() - tCifTablaIni;

            out.writeInt(iv1.length); out.write(iv1);
            out.writeInt(ct1.length); out.write(ct1);
            out.writeInt(hm1.length); out.write(hm1);

            // 5) Recibir petición ID cifrado + HMAC
            int iv2l = in.readInt(); byte[] iv2 = new byte[iv2l]; in.readFully(iv2);
            int ct2l = in.readInt(); byte[] ct2 = new byte[ct2l]; in.readFully(ct2);
            int hm2l = in.readInt(); byte[] hm2 = new byte[hm2l]; in.readFully(hm2);

            long tVerIni = System.nanoTime();
            if (!CriptoUtils.verificarHMAC(keys.keyHmac, ct2, hm2)) return;
            byte[] idB = CriptoUtils.descifrarAES(keys.keyEnc, iv2, ct2);
            long tVerif = System.nanoTime() - tVerIni;

            int idReq = Integer.parseInt(new String(idB).trim());
            ServidorPrincipal.Servicio svc =
                tabla.getOrDefault(idReq,
                    new ServidorPrincipal.Servicio(-1, "", "-1", -1));
            String resp = svc.ip + ":" + svc.puerto;

            // 6) Cifrado simétrico de la respuesta + HMAC
            long tCifRespSimIni = System.nanoTime();
            byte[] iv3 = CriptoUtils.generarIV();
            byte[] ct3 = CriptoUtils.cifrarAES(keys.keyEnc, iv3, resp.getBytes());
            byte[] hm3 = CriptoUtils.calcularHMAC(keys.keyHmac, ct3);
            long tCifRespSim = System.nanoTime() - tCifRespSimIni;

            out.writeInt(iv3.length); out.write(iv3);
            out.writeInt(ct3.length); out.write(ct3);
            out.writeInt(hm3.length); out.write(hm3);

            // 7) Cifrado asimétrico de la respuesta (para comparación)
            long tCifRespAsimIni = System.nanoTime();
            Cipher rsaC = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaC.init(Cipher.ENCRYPT_MODE, rsaPublic);
            rsaC.doFinal(resp.getBytes());
            long tCifRespAsim = System.nanoTime() - tCifRespAsimIni;

            // 8) Imprimir todos los tiempos
            System.out.printf(
              "[Delegado] firma=%d ns, cifTabla=%d ns, verif=%d ns, " +
              "cifRespSim=%d ns, cifRespAsim=%d ns%n",
              tFirma, tCifTabla, tVerif, tCifRespSim, tCifRespAsim
            );

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
