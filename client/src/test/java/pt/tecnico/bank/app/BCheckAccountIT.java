package pt.tecnico.bank.app;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pt.tecnico.bank.Crypto;
import pt.tecnico.bank.grpc.CheckAccountResponse;

import java.security.KeyPair;
import java.security.PublicKey;
import static org.junit.jupiter.api.Assertions.*;

public class BCheckAccountIT {

    private ServerFrontend frontend;
    private Crypto crypto;
    private App app;

    @BeforeEach
    public void setUp() {
        this.crypto = new Crypto();
        this.frontend = new ServerFrontend(1, this.crypto);
        this.app = new App(frontend, this.crypto);
    }

    @AfterEach
    public void tearDown() {
        this.frontend.close();
        this.frontend = null;
        this.app = null;
    }

    @Test
    public void checkAccountTest() {
        String username = "diogo";
        String password = "password1";
        KeyPair keyPair = crypto.getKeyPair(username, password);
        frontend.keyPair = keyPair;
        String usernameToCheck = "goncalo";
        PublicKey publicKey = crypto.getPubKeyfromCert(usernameToCheck);

        CheckAccountResponse response = app.checkAccount(publicKey, keyPair);
        assertEquals("valid", response.getMessage());
        assertEquals(500, response.getBalance());
        assertEquals(0, response.getTransactionsList().size());
        assertEquals(1, response.getRid());
        assertEquals(0, response.getWid());
    }

    @Test
    public void checkAccountTest2() {
        String username = "bernardo";
        String password = "password1";
        KeyPair keyPair = crypto.getKeyPair(username, password);
        frontend.keyPair = keyPair;
        String usernameToCheck = "goncalo";
        PublicKey publicKey = crypto.getPubKeyfromCert(usernameToCheck);

        CheckAccountResponse response = app.checkAccount(publicKey, keyPair);
        assertEquals("valid", response.getMessage());
        assertEquals(500, response.getBalance());
        assertEquals(0, response.getTransactionsList().size());
        assertEquals(1, response.getRid());
        assertEquals(0, response.getWid());
    }

    @Test
    public void checkAccountTest3() {
        String username = "goncalo";
        String password = "password1";
        KeyPair keyPair = crypto.getKeyPair(username, password);
        frontend.keyPair = keyPair;
        String usernameToCheck = "bernardo";
        PublicKey publicKey = crypto.getPubKeyfromCert(usernameToCheck);

        CheckAccountResponse response = app.checkAccount(publicKey, keyPair);
        assertEquals("valid", response.getMessage());
        assertEquals(500, response.getBalance());
        assertEquals(0, response.getTransactionsList().size());
        assertEquals(1, response.getRid());
        assertEquals(0, response.getWid());
    }
}
