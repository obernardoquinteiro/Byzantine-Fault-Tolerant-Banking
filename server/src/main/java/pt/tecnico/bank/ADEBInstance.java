package pt.tecnico.bank;

import java.util.concurrent.CountDownLatch;

public class ADEBInstance {

    private CountDownLatch latch;
    private int echos;
    private int readys;
    private boolean sentReady;

    public ADEBInstance() {
        latch = new CountDownLatch(1);
        this.echos = 0;
        this.readys = 0;
    }

    public void addEcho() { this.echos++; }
    public void addReady() { this.readys++; }
    public void await() {
        try {
            this.latch.await();
        } catch (InterruptedException e){
            System.out.println("AWAIT ERROR");
        }
    }

    public void deliver() { latch.countDown(); }

    public int getEchos() { return this.echos; }
    public int getReadys() { return this.readys; }

    public boolean hasSentReady() { return this.sentReady; }
    public void setHasSentReady() { this.sentReady = true; }

    public boolean hasDelivered() { return latch.getCount() == 0; }
}
