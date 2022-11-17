package pt.tecnico.bank.app;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pt.tecnico.bank.Crypto;
import pt.tecnico.bank.grpc.AuditResponse;
import pt.tecnico.bank.grpc.CheckAccountResponse;

import java.security.KeyPair;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class FByzantineIT {

    private ByzantineClientFrontend frontend;
    private Crypto crypto;
    private AppByzantine app;

    @BeforeEach
    public void setUp() {
        this.crypto = new Crypto();
        this.frontend = new ByzantineClientFrontend(1, this.crypto);
        this.app = new AppByzantine(frontend, this.crypto);
    }

    @AfterEach
    public void tearDown() {
        this.frontend.close();
        this.frontend = null;
        this.app = null;
    }

    @Test
    public void checkAccountTestManIntheMiddle() {
        String username = "diogo";
        String password = "password1";
        KeyPair keyPair = crypto.getKeyPair(username, password);
        frontend.keyPair = keyPair;
        String usernameToCheck = "goncalo";
        PublicKey publicKey = crypto.getPubKeyfromCert(usernameToCheck);

        CheckAccountResponse response = app.checkAccount(publicKey, keyPair);
        assertNull(response);
    }

    // ONE BYZANTINE
    @Test
    public void checkAccountTest2() {
        String username = "diogo";
        String password = "password1";
        KeyPair keyPair = crypto.getKeyPair(username, password);
        frontend.keyPair = keyPair;
        String usernameToCheck = "goncalo";
        PublicKey publicKey = crypto.getPubKeyfromCert(usernameToCheck);

        CheckAccountResponse response = app.checkAccount2(publicKey, keyPair);
        assertEquals("valid", response.getMessage());
    }

    // TWO BYZANTINE
    @Test
    public void checkAccountTest3() {
        String username = "diogo";
        String password = "password1";
        KeyPair keyPair = crypto.getKeyPair(username, password);
        frontend.keyPair = keyPair;
        String usernameToCheck = "goncalo";
        PublicKey publicKey = crypto.getPubKeyfromCert(usernameToCheck);

        CheckAccountResponse response = app.checkAccount3(publicKey, keyPair);
        assertNull(response);
    }

    @Test
    public void auditTestManInTheMiddle() {
        String username = "diogo";
        String password = "password1";
        KeyPair keyPair = crypto.getKeyPair(username, password);
        frontend.keyPair = keyPair;
        String usernameToCheck = "diogo";
        PublicKey publicKey = crypto.getPubKeyfromCert(usernameToCheck);

        AuditResponse response = app.audit(publicKey, keyPair, usernameToCheck);
        assertNull(response);
    }

    @Test
    public void auditOneByzantine() {
        String username = "diogo";
        String password = "password1";
        KeyPair keyPair = crypto.getKeyPair(username, password);
        frontend.keyPair = keyPair;
        String usernameToCheck = "diogo";
        PublicKey publicKey = crypto.getPubKeyfromCert(usernameToCheck);

        AuditResponse response = app.auditOneByzantine(publicKey, keyPair, usernameToCheck);
        assertEquals("valid", response.getMessage());
    }

    @Test
    public void auditTwoByzantine() {
        String username = "diogo";
        String password = "password1";
        KeyPair keyPair = crypto.getKeyPair(username, password);
        frontend.keyPair = keyPair;
        String usernameToCheck = "diogo";
        PublicKey publicKey = crypto.getPubKeyfromCert(usernameToCheck);

        AuditResponse response = app.auditTwoByzantine(publicKey, keyPair, usernameToCheck);
        assertNull(response);
    }
}
