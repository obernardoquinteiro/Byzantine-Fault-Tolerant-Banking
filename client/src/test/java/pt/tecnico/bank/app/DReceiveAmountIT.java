package pt.tecnico.bank.app;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pt.tecnico.bank.Crypto;
import pt.tecnico.bank.grpc.CheckAccountResponse;
import pt.tecnico.bank.grpc.ReceiveAmountResponse;
import pt.tecnico.bank.grpc.SendAmountResponse;

import java.security.KeyPair;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class DReceiveAmountIT {

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
    public void receiveAmountTest() {
        String username = "goncalo";
        String password = "password1";
        KeyPair keyPair = crypto.getKeyPair(username, password);
        frontend.keyPair = keyPair;
        int transactionNumber = 0;

        ReceiveAmountResponse response = app.receiveAmount(keyPair.getPublic(), transactionNumber, keyPair.getPrivate());
        assertEquals("valid", response.getMessage());
        assertEquals(1, response.getWid());

        CheckAccountResponse responseCheckMe = app.checkAccount(keyPair.getPublic(), keyPair);
        assertEquals("valid", responseCheckMe.getMessage());
        assertEquals(550, responseCheckMe.getBalance());
        assertEquals(0, responseCheckMe.getTransactionsList().size());
    }

    @Test
    public void receiveAmountWrongTransaction() {
        String username = "bernardo";
        String password = "password1";
        KeyPair keyPair = crypto.getKeyPair(username, password);
        frontend.keyPair = keyPair;
        int transactionNumber = 1;

        ReceiveAmountResponse response = app.receiveAmount(keyPair.getPublic(), transactionNumber, keyPair.getPrivate());
        assertNull(response);
    }
}
