package pt.tecnico.bank;

import io.grpc.stub.StreamObserver;

import java.util.concurrent.CountDownLatch;


public class ObserverADEB<R> implements StreamObserver<R> {

    public ObserverADEB() {
    }

    @Override
    public void onNext(R r) {

    }

    @Override
    public void onError(Throwable throwable) {
    }

    @Override
    public void onCompleted() {
    }
}