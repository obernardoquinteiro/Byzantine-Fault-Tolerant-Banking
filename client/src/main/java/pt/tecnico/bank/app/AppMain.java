package pt.tecnico.bank.app;

import pt.tecnico.bank.Crypto;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class AppMain {


	public static void main(String[] args) {

		// Initialization of the server frontend and App object
		Crypto crypto = new Crypto();

		int byzantine = Integer.parseInt(args[0]);
		ServerFrontend frontend = new ServerFrontend(byzantine, crypto);
		App app = new App(frontend, crypto);

		Scanner scanner = new Scanner(System.in);
		String scanned, receiverUsername, username, accountUsername = null, accountPassword;
		int amount, transactionNumber;

		KeyPair keyPair = null;
		boolean logout = true;
		boolean login = false;

		while (!login) {
			System.out.print("" +
					"\n1) Open Account" +
					"\n2) Load Account" +
					"\n3) Quit" +
					"\nSelect Operation: ");

			scanned = scanner.nextLine();

			switch (scanned) {
				case "1":
					System.out.print("\nChoose your account username: ");
					accountUsername = scanner.nextLine();
					System.out.print("Choose your account password: ");
					accountPassword = scanner.nextLine();
					if (accountUsername.equals("")){
						System.out.println("Username can't be null.");
					}
					else if (accountPassword.length() < 6) {
						System.out.println("Password has to be at least 6 characters long.");
					}
					else if (!existsAccount(accountUsername)) {
						generateStoreandCer(accountUsername, accountPassword);
						keyPair = getKeyPair(accountUsername, accountPassword);
						if (app.openAccount(keyPair.getPublic(), accountUsername, keyPair.getPrivate())) {
							logout = false;
							frontend.keyPair = keyPair;
						}
					} else {
						System.out.println("\nAccount already exists.");
					}
					break;

				case "2":
					System.out.print("\nAccount username: ");
					accountUsername = scanner.nextLine();
					System.out.print("Account password: ");
					accountPassword = scanner.nextLine();
					if (checkCredentials(accountUsername, accountPassword)) {
						keyPair = getKeyPair(accountUsername, accountPassword);
						logout = false;
						frontend.keyPair = keyPair;
						System.out.println("\nSuccessfully logged in.");
						app.getRid(keyPair.getPublic());
					}
					break;

				case "3":
					login = true;
					System.out.println("Exiting the app.");
					frontend.close();
					break;

				default:
					System.out.println("WARNING invalid input.");
					break;
			}

			while (!logout) {

				System.out.print("" +
						"\n1) Check Account" +
						"\n2) Send Amount" +
						"\n3) Receive Amount" +
						"\n4) Audit" +
						"\n5) Ping" +
						"\n6) Logout" +
						"\nSelect Operation: ");

				scanned = scanner.nextLine();

				switch (scanned) {

					case "1":
						System.out.print("\nAccount username: ");
						username = scanner.nextLine();
						if (existsAccount(username)){
							app.checkAccount(getPubKeyfromCert(username), keyPair);
						} else {
							System.out.println("No account found with that username.");
						}
						break;

					case "2":
						System.out.print("\nReceiver username: ");
						receiverUsername = scanner.nextLine();
						System.out.print("Amount: ");
						amount = Integer.parseInt(scanner.nextLine());
						if (!receiverUsername.equals(accountUsername)) {
							if (existsAccount(receiverUsername)) {
								app.sendAmount(keyPair.getPublic(), getPubKeyfromCert(receiverUsername), amount, keyPair.getPrivate(), accountUsername, receiverUsername);
							} else {
								System.out.println("No account found with that username.");
							}
						} else {
							System.out.println("Can't send money to yourself!");
						}
						break;
					case "3":
						System.out.print("\nTransaction number: ");
						transactionNumber = Integer.parseInt(scanner.nextLine()) - 1;
						app.receiveAmount(keyPair.getPublic(), transactionNumber, keyPair.getPrivate());
						break;

					case "4":
						System.out.print("\nAccount username: ");
						username = scanner.nextLine();
						if (existsAccount(username)) {
							app.audit(getPubKeyfromCert(username), keyPair, username);
						} else {
							System.out.println("No account found with that username.");
						}
						break;

					case "5":
						app.ping();
						break;

					case "6":
						logout = true;
						System.out.println("Logging out.");
						break;

					default:
						System.out.println("WARNING invalid input.");
						break;
				}
			}
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

	public static boolean checkCredentials(String username, String password) {
		try {
			FileInputStream is = new FileInputStream("Keystores/" + username + ".jks");
			KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			char[] passwd = password.toCharArray();
			keystore.load(is, passwd);
			return true;
		} catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e){
			System.out.println("\nWrong Credentials.");
			return false;
		}
	}
	
	public static boolean existsAccount(String username) {
		try {
			new FileInputStream("Certificates/" + username + ".cer");
			return true;
		} catch (FileNotFoundException e) {
			return false;
		}
	}
}
