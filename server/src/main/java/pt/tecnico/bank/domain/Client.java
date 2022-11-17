package pt.tecnico.bank.domain;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

public class Client implements Serializable {
    private String username;
    private int balance;
    private List<Transactions> pending;
    private List<Transactions> history;
    private int wid;
    private int rid;
    private byte [] pair_signature;
    private HashSet<Integer> eventList;
    private byte[] challenge;

    public Client(String username, byte [] pair_signature) {
        this.username = username;
        this.balance = 500;
        this.pending = new ArrayList<>();
        this.history = new ArrayList<>();
        this.wid = 0;
        this.rid = 0;
        this.pair_signature = pair_signature;
        this.eventList = new HashSet<>();
        this.challenge = null;
    }

    public int getBalance(){ return balance; }
    public void setBalance(int balance) { this.balance = balance; }

    public List<Transactions> getPending() { return pending; }
    public void removePending (int index) {
        this.pending.remove(index);
    }
    public void addPending (Transactions transaction) {
        this.pending.add(transaction);
    }
    public void setPending (List<Transactions> list) { this.pending = list; }

    public List<Transactions> getHistory() { return history; }
    public void addHistory (Transactions transaction) {
        this.history.add(transaction);
    }
    public void setHistory (List<Transactions> list) { this.history = list; }

    public int getWid() { return this.wid; }
    public int getRid() { return this.rid; }

    public byte[] getPair_signature() { return pair_signature; }
    public void setPairSign(byte[] pair_signature) { this.pair_signature = pair_signature; }

    public void setWid(int value) { this.wid = value; }
    public void setRid(int value) { this.rid = value; }

    public HashSet<Integer> getEventList() { return this.eventList; }
    public void addEvent(int nonce) { this.eventList.add(nonce); }

    public byte[] getChallenge() { return this.challenge; }
    public void setChallenge(byte[] challenge) { this.challenge = challenge; }
}
