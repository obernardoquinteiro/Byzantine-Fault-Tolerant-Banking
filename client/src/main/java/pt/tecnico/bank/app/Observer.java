package pt.tecnico.bank.app;

import io.grpc.stub.StreamObserver;

import java.util.concurrent.CountDownLatch;

public class Observer<R> implements StreamObserver<R> {

    final RespCollector collector;
    final CountDownLatch finishLatch;

    public Observer(RespCollector collector, CountDownLatch fLatch) {
        this.collector = collector;
        this.finishLatch = fLatch;
    }

    @Override
    public void onNext(R r) {
        if (this.collector != null) {
            collector.responses.add(r);
        }
    }

    @Override
    public void onError(Throwable throwable) {
    }

    @Override
    public void onCompleted() {
        finishLatch.countDown();
    }
}
