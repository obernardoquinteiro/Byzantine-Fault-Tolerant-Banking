package pt.tecnico.bank;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Crypto {

    private int powDifficulty = 2;

    public Crypto() { }

    public int getSecureRandom() {
        try {
            return SecureRandom.getInstance("SHA1PRNG").nextInt();
        } catch (NoSuchAlgorithmException e){
            System.out.println("Wrong Algorithm.");
            return 0;
        }
    }

    public static void generateStoreandCer(String username, String password) {

        try {
            String[] keystore_array = new String[14];
            keystore_array[0] = "keytool";
            keystore_array[1] = "-genkey";
            keystore_array[2] = "-alias";
            keystore_array[3] = username;
            keystore_array[4] = "-keyalg";
            keystore_array[5] = "RSA";
            keystore_array[6] = "-keystore";
            keystore_array[7] = "Keystores/" + username + ".jks";
            keystore_array[8] = "-dname";
            keystore_array[9] = "CN=mqttserver.ibm.com, OU=ID, O=IBM, L=Hursley, S=Hantes, C=GB";
            keystore_array[10] = "-storepass";
            keystore_array[11] = password;
            keystore_array[12] = "-keypass";
            keystore_array[13] = password;

            ProcessBuilder builder = new ProcessBuilder(keystore_array);
            Process process = builder.start();
            process.waitFor();

            String[] certificate = new String[11];
            certificate[0] = "keytool";
            certificate[1] = "-v";
            certificate[2] = "-export";
            certificate[3] = "-alias";
            certificate[4] = username;
            certificate[5] = "-file";
            certificate[6] = "Certificates/" + username + ".cer";
            certificate[7] = "-keystore";
            certificate[8] = "Keystores/" + username + ".jks";
            certificate[9] = "-storepass";
            certificate[10] = password;

            builder.command(certificate).start();

        } catch (IOException | InterruptedException e) {
            System.out.println("ERROR while running Keytool commands.");
        }
    }

    public static KeyPair getKeyPair(String username, String password) {
        try {
            FileInputStream is = new FileInputStream("Keystores/" + username + ".jks");
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] passwd = password.toCharArray();
            keystore.load(is, passwd);
            Key key = keystore.getKey(username, passwd);
            Certificate cert = keystore.getCertificate(username);
            PublicKey publicKey = cert.getPublicKey();
            return new KeyPair(publicKey, (PrivateKey) key);

        } catch (IOException | CertificateException | UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            System.out.println("ERROR while retrieving keypair from keystore.");
            return null;
        }
    }

    public static PublicKey getPubKeyfromCert(String username) {
        try {
            FileInputStream fin = new FileInputStream("Certificates/" + username + ".cer");
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            X509Certificate certificate1 = (X509Certificate) f.generateCertificate(fin);
            return certificate1.getPublicKey();
        } catch (FileNotFoundException | CertificateException e) {
            System.out.println("ERROR while retrieving public key from certificate.");
            return null;
        }
    }

    public byte[] getSignature(String finalString, PrivateKey privateKey) {
        try {
            Signature dsaForSign = Signature.getInstance("SHA256withRSA");
            dsaForSign.initSign(privateKey);
            dsaForSign.update(finalString.getBytes());
            return dsaForSign.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println("Something went wrong while signing.");
            return null;
        }
    }

    public boolean verifySignature(String finalString, PublicKey publicKey, byte[] signature){
        try {
            Signature dsaForVerify = Signature.getInstance("SHA256withRSA");
            dsaForVerify.initVerify(publicKey);
            dsaForVerify.update(finalString.getBytes());
            return dsaForVerify.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e){
            System.out.println("Signatures don't match.");
            return false;
        }
    }

    public PublicKey getPubKeyGrpc(byte[] pubKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubKey));
    }

    public long generateProofOfWork(byte[] bytes) {
        long pow = 0L;
        while (!verifyProofOfWork(bytes, pow)) pow++;
        return pow;
    }

    public boolean verifyProofOfWork(byte[] bytes, long pow) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash =
                    md.digest(ByteBuffer.allocate(bytes.length + Long.BYTES).put(bytes).putLong(pow).array());
            for (int i = 0; i < this.powDifficulty; i++) {
                if (hash[i] != 0) return false;
            }
            return true;
        } catch (NoSuchAlgorithmException e) {
            System.out.println("No such algorithm!");
            return false;
        }
    }

}
