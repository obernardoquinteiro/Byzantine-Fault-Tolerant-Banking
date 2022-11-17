package pt.tecnico.bank.domain;

import java.io.Serializable;
import java.security.PublicKey;

public class Transactions implements Serializable {
    private String senderUsername;
    private String destUsername;
    private int value;
    private PublicKey sourcePublicKey;
    private PublicKey destinationPublicKey;
    int wid;
    private byte[] signature;

    public Transactions(String senderUsername, String destUsername, int value, PublicKey sourcePublicKey, PublicKey destinationPublicKey, int wid, byte[] signature){
        this.senderUsername = senderUsername;
        this.destUsername = destUsername;
        this.value = value;
        this.sourcePublicKey = sourcePublicKey;
        this.destinationPublicKey = destinationPublicKey;
        this.wid = wid;
        this.signature = signature;
    }

    public String getSenderUsername() {
        return this.senderUsername;
    }

    public String getDestUsername() { return this.destUsername; }

    public int getValue() {
        return value;
    }

    public void setValue(int value) { this.value = value; }

    public PublicKey getSourceKey() { return this.sourcePublicKey; }

    public PublicKey getDestKey() { return this.destinationPublicKey; }

    public int getWid() { return this.wid; }

    public byte[] getSignature() { return this.signature; }
}
