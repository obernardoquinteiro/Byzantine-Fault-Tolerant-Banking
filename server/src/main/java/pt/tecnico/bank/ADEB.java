package pt.tecnico.bank;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import pt.tecnico.bank.grpc.ADEBServiceGrpc;
import pt.tecnico.bank.grpc.EchoRequest;
import pt.tecnico.bank.grpc.ReadyRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static pt.tecnico.bank.ServerMain.*;

public class ADEB implements AutoCloseable {

    private int byzantine;
    private final List<ManagedChannel> channels;
    private final List<ADEBServiceGrpc.ADEBServiceStub> stubs;
    private int nServers;
    private String serverName;
    private int quorum;

    public ADEB(int byzantine, String serverName) {
        this.byzantine = byzantine;
        this.channels = new ArrayList<>();
        this.stubs = new ArrayList<>();
        this.nServers = 3*byzantine + 1;
        this.serverName = serverName;
        this.quorum = 2 * byzantine + 1;

        for (int i = 0; i < nServers; i++){
            ManagedChannel channel = ManagedChannelBuilder.forAddress("localhost", 8080 + i).usePlaintext().build();
            channels.add(channel);
            stubs.add(ADEBServiceGrpc.newStub(channel));
        }
    }

    public void echo(String input) {

        System.out.println("Receiving echos...");

        int nonce = crypto.getSecureRandom();

        String finalString = input + nonce + serverName;

        EchoRequest request = EchoRequest.newBuilder()
                .setSignature(ByteString.copyFrom(crypto.getSignature(finalString, keyPair.getPrivate())))
                .setServerPubkey(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .setNonce(nonce)
                .setServerName(serverName)
                .setInput(input)
                .build();

        for (ADEBServiceGrpc.ADEBServiceStub stub : this.stubs) {
            stub.withDeadlineAfter(3, TimeUnit.SECONDS).echo(request, new ObserverADEB<>());
        }
    }

    public void ready(String input) {

        System.out.println("Receiving readys...");

        int nonce = crypto.getSecureRandom();

        String finalString = input + nonce + serverName;

        ReadyRequest request = ReadyRequest.newBuilder()
                .setSignature(ByteString.copyFrom(crypto.getSignature(finalString, keyPair.getPrivate())))
                .setServerPubkey(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .setNonce(nonce)
                .setServerName(serverName)
                .setInput(input)
                .build();

        for (ADEBServiceGrpc.ADEBServiceStub stub : this.stubs) {
            stub.withDeadlineAfter(3, TimeUnit.SECONDS).ready(request, new ObserverADEB<>());
        }
    }

    public int getQuorum() { return this.quorum; }

    @Override
    public final void close() {
        this.channels.forEach(ManagedChannel::shutdown);
    }
}
