package seguridad;

import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;

public class ServidorPrincipal {
    private static final int PUERTO = 8000;
    private PublicKey rsaPublic;
    private PrivateKey rsaPrivate;
    private Map<Integer, Servicio> tablaServicios;

    public static void main(String[] args) throws Exception {
        ServidorPrincipal server = new ServidorPrincipal();
        server.cargarLlaves();
        System.out.println("Llaves RSA cargadas.");

        server.inicializarTabla();
        System.out.println("Tabla de servicios inicializada.");

        System.out.println("ServidorPrincipal escuchando en puerto " + PUERTO);
        server.escuchar();
    }

    private void cargarLlaves() throws Exception {
        byte[] pub = Files.readAllBytes(Path.of("llaves/public.key"));
        byte[] priv = Files.readAllBytes(Path.of("llaves/private.key"));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        rsaPublic = kf.generatePublic(new X509EncodedKeySpec(pub));
        rsaPrivate = kf.generatePrivate(new PKCS8EncodedKeySpec(priv));
    }

    private void inicializarTabla() {
        tablaServicios = new HashMap<>();
        tablaServicios.put(1, new Servicio(1, "Estado vuelo", "127.0.0.1", 9001));
        tablaServicios.put(2, new Servicio(2, "Disponibilidad vuelos", "127.0.0.1", 9002));
        tablaServicios.put(3, new Servicio(3, "Costo de un vuelo", "127.0.0.1", 9003));
    }

    private void escuchar() throws Exception {
        ServerSocket ss = new ServerSocket(PUERTO);
        while (true) {
            Socket cliente = ss.accept();
            new Thread(new DelegadoServidor(cliente, rsaPublic, rsaPrivate, tablaServicios)).start();
        }
    }

    public static class Servicio {
        public final int id;
        public final String nombre, ip;
        public final int puerto;
        public Servicio(int id, String n, String ip, int p) {
            this.id = id; this.nombre = n; this.ip = ip; this.puerto = p;
        }
    }
}