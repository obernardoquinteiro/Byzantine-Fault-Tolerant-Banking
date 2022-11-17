package pt.tecnico.bank.app;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pt.tecnico.bank.Crypto;
import pt.tecnico.bank.grpc.CheckAccountResponse;
import pt.tecnico.bank.grpc.SendAmountResponse;

import java.security.KeyPair;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CSendAmountIT {

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
    public void sendAmountTest() {
        String username = "diogo";
        String password = "password1";
        KeyPair keyPair = crypto.getKeyPair(username, password);
        frontend.keyPair = keyPair;
        String usernameToSend = "goncalo";
        PublicKey publicKey = crypto.getPubKeyfromCert(usernameToSend);

        SendAmountResponse response = app.sendAmount(keyPair.getPublic(), publicKey, 50, keyPair.getPrivate(), username, usernameToSend);
        assertEquals("valid", response.getMessage());
        assertEquals(1, response.getWid());

        CheckAccountResponse responseCheckOther = app.checkAccount(publicKey, keyPair);
        assertEquals("valid", responseCheckOther.getMessage());
        assertEquals(500, responseCheckOther.getBalance());
        assertEquals(1, responseCheckOther.getTransactionsList().size());
        assertEquals(50, responseCheckOther.getTransactionsList().get(0).getAmount());
        assertEquals("diogo", responseCheckOther.getTransactionsList().get(0).getSourceUsername());
        assertEquals(0, responseCheckOther.getWid());

        CheckAccountResponse responseCheckMe = app.checkAccount(keyPair.getPublic(), keyPair);
        assertEquals("valid", responseCheckMe.getMessage());
        assertEquals(450, responseCheckMe.getBalance());
        assertEquals(0, responseCheckMe.getTransactionsList().size());
    }

    @Test
    public void sendAmountNotEnoughBalance() {
        String username = "bernardo";
        String password = "password1";
        KeyPair keyPair = crypto.getKeyPair(username, password);
        frontend.keyPair = keyPair;
        String usernameToSend = "goncalo";
        PublicKey publicKey = crypto.getPubKeyfromCert(usernameToSend);

        SendAmountResponse response = app.sendAmount(keyPair.getPublic(), publicKey, 600, keyPair.getPrivate(), username, usernameToSend);
        assertEquals("Sender account does not have enough balance.", response.getMessage());
    }

    @Test
    public void sendAmountNegativeAmount() {
        String username = "bernardo";
        String password = "password1";
        KeyPair keyPair = crypto.getKeyPair(username, password);
        frontend.keyPair = keyPair;
        String usernameToSend = "goncalo";
        PublicKey publicKey = crypto.getPubKeyfromCert(usernameToSend);

        SendAmountResponse response = app.sendAmount(keyPair.getPublic(), publicKey, -20, keyPair.getPrivate(), username, usernameToSend);
        assertEquals("Invalid amount, must be > 0.", response.getMessage());
    }
}
