package seguridad;

  import javax.crypto.*;
  import javax.crypto.spec.*;
  import java.math.BigInteger;
  import java.security.*;
  import java.security.spec.*;
  
  public class CriptoUtils {
      private static final SecureRandom RNG = new SecureRandom();
  
      // Genera un par de claves RSA de 1024 bits
      public static KeyPair generarClavesRSA() throws NoSuchAlgorithmException {
          KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
          kpg.initialize(1024);
          return kpg.generateKeyPair();
      }
  
      // Genera parámetros DH de 1024 bits
      public static DHParameterSpec generarParametrosDH() throws NoSuchAlgorithmException, InvalidParameterSpecException {
          AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance("DH");
          apg.init(1024);
          AlgorithmParameters params = apg.generateParameters();
          return params.getParameterSpec(DHParameterSpec.class);
      }
  
      // Genera pares de clave DH con un spec dado
      public static KeyPair generarClavesDH(DHParameterSpec spec) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
          KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
          kpg.initialize(spec);
          return kpg.generateKeyPair();
      }
  
      // Deriva llaves de sesión (AES y HMAC) a partir del secreto DH compartido
      public static SecretKeys derivarLlaves(byte[] sharedSecret) throws NoSuchAlgorithmException {
          MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
          byte[] hash = sha512.digest(sharedSecret);
          byte[] keyEnc = new byte[32];
          byte[] keyHmac = new byte[32];
          System.arraycopy(hash, 0, keyEnc, 0, 32);
          System.arraycopy(hash, 32, keyHmac, 0, 32);
          return new SecretKeys(keyEnc, keyHmac);
      }
  
      // Generación de un IV de 16 bytes aleatorio
      public static byte[] generarIV() {
          byte[] iv = new byte[16];
          RNG.nextBytes(iv);
          return iv;
      }
  
      // AES-CBC/PKCS5Padding cifrado
      public static byte[] cifrarAES(byte[] key, byte[] iv, byte[] data) throws Exception {
          Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
          SecretKeySpec k = new SecretKeySpec(key, "AES");
          cipher.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
          return cipher.doFinal(data);
      }
  
      // AES-CBC/PKCS5Padding descifrado
      public static byte[] descifrarAES(byte[] key, byte[] iv, byte[] cipherText) throws Exception {
          Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
          SecretKeySpec k = new SecretKeySpec(key, "AES");
          cipher.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
          return cipher.doFinal(cipherText);
      }
  
      // Cálculo de HMAC-SHA256
      public static byte[] calcularHMAC(byte[] key, byte[] data) throws Exception {
          Mac mac = Mac.getInstance("HmacSHA256");
          SecretKeySpec k = new SecretKeySpec(key, "HmacSHA256");
          mac.init(k);
          return mac.doFinal(data);
      }
  
      // Verifica HMAC-SHA256 
      public static boolean verificarHMAC(byte[] key, byte[] data, byte[] hmacToCheck) throws Exception {
          byte[] calc = calcularHMAC(key, data);
          if (calc.length != hmacToCheck.length) return false;
          int res = 0;
          for (int i = 0; i < calc.length; i++) res |= calc[i] ^ hmacToCheck[i];
          return res == 0;
      }
  
      // Firma RSA (SHA256withRSA)
      public static byte[] firmarRSA(PrivateKey priv, byte[] data) throws Exception {
          Signature sig = Signature.getInstance("SHA256withRSA");
          sig.initSign(priv);
          sig.update(data);
          return sig.sign();
      }
  
      // Verifica firma RSA
      public static boolean verificarRSA(PublicKey pub, byte[] data, byte[] firma) throws Exception {
          Signature sig = Signature.getInstance("SHA256withRSA");
          sig.initVerify(pub);
          sig.update(data);
          return sig.verify(firma);
      }
  }

// Clase auxiliar para llaves simétricas
class SecretKeys {
    public final byte[] keyEnc;
    public final byte[] keyHmac;
    public SecretKeys(byte[] enc, byte[] hmac) { this.keyEnc = enc; this.keyHmac = hmac; }
}