package pt.tecnico.bank.app;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pt.tecnico.bank.Crypto;
import pt.tecnico.bank.grpc.AuditResponse;
import pt.tecnico.bank.grpc.CheckAccountResponse;
import pt.tecnico.bank.grpc.ReceiveAmountResponse;

import java.security.KeyPair;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;


public class EAuditIT {

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
    public void auditTest() {
        String username = "diogo";
        String password = "password1";
        KeyPair keyPair = crypto.getKeyPair(username, password);
        frontend.keyPair = keyPair;
        String usernameToCheck = "diogo";
        PublicKey publicKey = crypto.getPubKeyfromCert(usernameToCheck);

        AuditResponse response = app.audit(publicKey, keyPair, usernameToCheck);
        assertEquals("valid", response.getMessage());
        assertEquals(1, response.getTransactionsList().size());
        assertEquals(1, response.getRid());
        assertEquals("goncalo", response.getTransactionsList().get(0).getDestUsername());
    }

    @Test
    public void auditTest2() {
        String username = "goncalo";
        String password = "password1";
        KeyPair keyPair = crypto.getKeyPair(username, password);
        frontend.keyPair = keyPair;
        String usernameToCheck = "goncalo";
        PublicKey publicKey = crypto.getPubKeyfromCert(usernameToCheck);

        AuditResponse response = app.audit(publicKey, keyPair, usernameToCheck);
        assertEquals("valid", response.getMessage());
        assertEquals(1, response.getTransactionsList().size());
        assertEquals(1, response.getRid());
        assertEquals("diogo", response.getTransactionsList().get(0).getSourceUsername());
    }
}
