package pt.tecnico.bank.app;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pt.tecnico.bank.Crypto;
import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;

public class AOpenAccountIT {

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
    public void OpenAccountTest1() throws InterruptedException {
        String username = "diogo";
        String password = "password1";
        crypto.generateStoreandCer(username, password);
        Thread.sleep(1500);
        KeyPair keyPair = crypto.getKeyPair(username, password);
        assertTrue(app.openAccount(keyPair.getPublic(), username, keyPair.getPrivate()));
    }

    @Test
    public void OpenAccountTest2() throws InterruptedException {
        String username = "bernardo";
        String password = "password1";
        crypto.generateStoreandCer(username, password);
        Thread.sleep(1500);
        KeyPair keyPair = crypto.getKeyPair(username, password);
        assertTrue(app.openAccount(keyPair.getPublic(), username, keyPair.getPrivate()));
    }

    @Test
    public void OpenAccountTest3() throws InterruptedException {
        String username = "goncalo";
        String password = "password1";
        crypto.generateStoreandCer(username, password);
        Thread.sleep(1500);
        KeyPair keyPair = crypto.getKeyPair(username, password);
        assertTrue(app.openAccount(keyPair.getPublic(), username, keyPair.getPrivate()));
    }

}
