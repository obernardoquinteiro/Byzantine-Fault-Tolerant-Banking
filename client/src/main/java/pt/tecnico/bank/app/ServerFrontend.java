package pt.tecnico.bank.app;

import com.google.common.primitives.Bytes;
import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import pt.tecnico.bank.Crypto;
import pt.tecnico.bank.grpc.*;

import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class ServerFrontend implements AutoCloseable {

    private final List<ManagedChannel> channels;
    private final List<ServerServiceGrpc.ServerServiceStub> stubs;
    private final int quorum;
    private final int byzantine;
    private final Crypto crypto;
    private HashMap<Integer, byte[]> proofs;
    private int numberChannels;
    KeyPair keyPair;

    public ServerFrontend(int value, Crypto crypto) {
        this.channels = new ArrayList<>();
        this.stubs = new ArrayList<>();
        this.numberChannels = 3 * value + 1;
        this.byzantine = value;
        this.quorum = 2 * value + 1;
        this.crypto = crypto;
        this.proofs = new HashMap<>();

        for (int i = 0; i < numberChannels; i++){
            ManagedChannel channel = ManagedChannelBuilder.forAddress("localhost", 8080 + i).usePlaintext().build();
            channels.add(channel);
            stubs.add(ServerServiceGrpc.newStub(channel));
        }
    }

    /* ---------- Services ---------- */

    public void proof() {

        RespCollector collector = new RespCollector();
        CountDownLatch finishLatch = new CountDownLatch(this.numberChannels);

        int nonce = crypto.getSecureRandom();

        String proofString = nonce + keyPair.getPublic().toString();
        byte[] signature = crypto.getSignature(proofString, keyPair.getPrivate());
        ProofOfWorkRequest proofRequest = ProofOfWorkRequest.newBuilder().setNonce(nonce)
                .setPublicKey(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .setSignature(ByteString.copyFrom(signature)).build();

        for (ServerServiceGrpc.ServerServiceStub stub : this.stubs) {
            stub.withDeadlineAfter(3, TimeUnit.SECONDS).proof(proofRequest, new Observer<>(collector, finishLatch));
        }

        try {
            finishLatch.await();
        } catch (InterruptedException e) {
            System.out.println("Error");
        }

        Iterator<Object> iterator = collector.responses.iterator();

        synchronized (collector.responses) {
            while (iterator.hasNext()) {
                ProofOfWorkResponse response = (ProofOfWorkResponse) iterator.next();

                try {
                    PublicKey serverPubKey = crypto.getPubKeyGrpc(response.getServerPubkey().toByteArray());
                    int nonceSever = response.getNonce();
                    byte[] challenge = response.getChallenge().toByteArray();
                    String finalString = nonceSever + Arrays.toString(challenge) + serverPubKey.toString() + response.getMessage() + response.getPort();
                    if (crypto.verifySignature(finalString, serverPubKey, response.getSignature().toByteArray())) {
                        proofs.put(response.getPort(), challenge);
                    }
                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    System.out.println("Something wrong with the algorithm!");
                }
            }
        }
    }

    public RidResponse rid(RidRequest request) {
        RespCollector collector = new RespCollector();

        CountDownLatch finishLatch = new CountDownLatch(quorum);

        for (ServerServiceGrpc.ServerServiceStub stub : this.stubs) {
            stub.withDeadlineAfter(3, TimeUnit.SECONDS).rid(request, new Observer<>(collector, finishLatch));
        }

        try {
            finishLatch.await();
        } catch (InterruptedException e) {
            System.out.println("Error");
        }

        Iterator<Object> iterator = collector.responses.iterator();
        int counter = 0;
        int rid = -1;
        RidResponse bestResponse = null;

        synchronized (collector.responses) {
            while (iterator.hasNext()) {
                RidResponse response = (RidResponse) iterator.next();
                try {
                    PublicKey serverPubKey = crypto.getPubKeyGrpc(response.getServerPubKey().toByteArray());
                    String finalString = serverPubKey.toString() + response.getRid() + response.getMessage();
                    if (!crypto.verifySignature(finalString, serverPubKey, response.getSignature().toByteArray())) {
                        iterator.remove();
                        counter++;
                    } else {
                        if (response.getRid() > rid){
                            bestResponse = response;
                        }
                    }
                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    System.out.println("Something wrong with the algorithm!");
                }
            }
        }

        if (counter > this.byzantine) {
            return null;
        } else {
            return bestResponse;
        }
    }

    public PingResponse ping(PingRequest request) {
        RespCollector collector = new RespCollector();

        CountDownLatch finishLatch = new CountDownLatch(quorum);

        for (ServerServiceGrpc.ServerServiceStub stub : this.stubs) {
            stub.withDeadlineAfter(3, TimeUnit.SECONDS).ping(request, new Observer<>(collector, finishLatch));
        }

        try {
            finishLatch.await();
        } catch (InterruptedException e) {
            System.out.println("Error");
        }

        return (PingResponse) collector.responses.get(0);
    }

    public OpenAccountResponse openAccount(OpenAccountRequest request) {

        RespCollector collector = new RespCollector();

        CountDownLatch finishLatch = new CountDownLatch(quorum);

        for (ServerServiceGrpc.ServerServiceStub stub : this.stubs) {
            stub.withDeadlineAfter(3, TimeUnit.SECONDS).openAccount(request, new Observer<>(collector, finishLatch));
        }

        try {
            finishLatch.await();
        } catch (InterruptedException e) {
            System.out.println("Error");
        }

        Iterator<Object> iterator = collector.responses.iterator();
        int counter = 0;

        synchronized (collector.responses) {
            while (iterator.hasNext()) {
                OpenAccountResponse response = (OpenAccountResponse) iterator.next();
                try {
                    PublicKey serverPubKey = crypto.getPubKeyGrpc(response.getPublicKey().toByteArray());
                    String finalString = serverPubKey.toString() + response.getMessage();
                    if (!crypto.verifySignature(finalString, serverPubKey, response.getSignature().toByteArray())) {
                        iterator.remove();
                        counter++;
                    }
                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    System.out.println("Something wrong with the algorithm!");
                }
            }
        }

        if (counter > this.byzantine) {
            return null;
        } else {
            return (OpenAccountResponse) collector.responses.get(0);
        }
    }

    public CheckAccountResponse checkAccount(CheckAccountRequest request) {

        proof();

        RespCollector collector = new RespCollector();

        CountDownLatch finishLatch = new CountDownLatch(quorum);

        int port = 8080;

        for (ServerServiceGrpc.ServerServiceStub stub : this.stubs) {

            byte [] challenge = proofs.get(port);
            byte [] concatenated = Bytes.concat(challenge, request.getMyPublicKey().toByteArray());
            long pow = crypto.generateProofOfWork(concatenated);

            CheckAccountRequest checkRequest = CheckAccountRequest.newBuilder()
                    .setPublicKey(request.getPublicKey())
                    .setMyPublicKey(request.getMyPublicKey())
                    .setRid(request.getRid())
                    .setNonce(request.getNonce())
                    .setPow(pow)
                    .setConcatenated(ByteString.copyFrom(concatenated))
                    .setSignature(request.getSignature())
                    .build();

            while (true) {
                try {
                    stub.withDeadlineAfter(3, TimeUnit.SECONDS).checkAccount(checkRequest, new Observer<>(collector, finishLatch));
                    break;
                } catch (StatusRuntimeException e) {
                    if (e.getStatus().getCode() == Status.DEADLINE_EXCEEDED.getCode()){
                        System.out.println("Stub error");
                    }
                }
            }
            port++;
        }

        try {
            finishLatch.await();
        } catch (InterruptedException e) {
            System.out.println("Error");
        }

        Iterator<Object> iterator = collector.responses.iterator();
        int counter = 0;
        int wid = -1;
        CheckAccountResponse bestResponse = null;

        synchronized (collector.responses) {
            while (iterator.hasNext()) {
                boolean fakeTransaction = false;
                CheckAccountResponse response = (CheckAccountResponse) iterator.next();
                try {
                    PublicKey serverPubKey = crypto.getPubKeyGrpc(response.getPublicKey().toByteArray());
                    String finalString = serverPubKey.toString() + response.getBalance()
                            + response.getWid() + Arrays.toString(response.getPairSign().toByteArray())
                            + response.getRid() + response.getMessage()
                            + response.getTransactionsList() + response.getNonce();

                    String pairSignString = String.valueOf(response.getBalance()) + response.getWid();

                    PublicKey otherPubK = crypto.getPubKeyGrpc(request.getPublicKey().toByteArray());

                    if (!crypto.verifySignature(finalString, serverPubKey, response.getSignature().toByteArray())
                            || request.getNonce() + 1 != response.getNonce()
                            || !crypto.verifySignature(pairSignString, otherPubK, response.getPairSign().toByteArray())
                            || request.getRid() != response.getRid()) {

                        iterator.remove();
                        counter++;

                    } else {
                        for (Transaction transaction : response.getTransactionsList()){
                            String transactionString = transaction.getSourceUsername() + transaction.getDestUsername()
                                    + transaction.getAmount() + crypto.getPubKeyGrpc(transaction.getSource().toByteArray())
                                    + crypto.getPubKeyGrpc(transaction.getDestination().toByteArray())
                                    + transaction.getWid();

                            PublicKey transactionPubK = crypto.getPubKeyGrpc(transaction.getSource().toByteArray());
                            if (!crypto.verifySignature(transactionString, transactionPubK, transaction.getSignature().toByteArray())) {
                                fakeTransaction = true;
                                break;
                            }
                        }

                        if (fakeTransaction) {
                            iterator.remove();
                            counter++;

                        } else {
                            if (response.getWid() > wid){
                                wid = response.getWid();
                                bestResponse = response;
                            }
                        }
                    }

                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    System.out.println("Something wrong with the algorithm!");
                }
            }
        }

        if (counter > this.byzantine) {
            return null;
        } else {
            return bestResponse;
        }
    }

    public SendAmountResponse sendAmount(SendAmountRequest request) {

        RespCollector collector = new RespCollector();

        CountDownLatch finishLatch = new CountDownLatch(quorum);

        for (ServerServiceGrpc.ServerServiceStub stub : this.stubs) {
            while (true) {
                try {
                    stub.withDeadlineAfter(3, TimeUnit.SECONDS).sendAmount(request, new Observer<>(collector, finishLatch));
                    break;
                } catch (StatusRuntimeException e) {
                    if (e.getStatus().getCode() == Status.DEADLINE_EXCEEDED.getCode()){
                        System.out.println("Stub error");
                    }
                }
            }
        }

        try {
            finishLatch.await();
        } catch (InterruptedException e) {
            System.out.println("Error");
        }

        Iterator<Object> iterator = collector.responses.iterator();
        int counter = 0;
        int wid = -1;
        SendAmountResponse bestResponse = null;

        synchronized (collector.responses) {
            while (iterator.hasNext()) {
                SendAmountResponse response = (SendAmountResponse) iterator.next();
                try {
                    PublicKey serverPubKey = crypto.getPubKeyGrpc(response.getPublicKey().toByteArray());
                    String finalString = serverPubKey.toString() + response.getMessage() + response.getWid();

                    if (!crypto.verifySignature(finalString, serverPubKey, response.getSignature().toByteArray())) {
                        iterator.remove();
                        counter++;

                    } else {
                        if (response.getWid() > wid){
                            wid = response.getWid();
                            bestResponse = response;
                        }
                    }

                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    System.out.println("Something wrong with the algorithm!");
                }
            }
        }

        if (counter > this.byzantine) {
            return null;
        } else {
            return bestResponse;
        }
    }

    public ReceiveAmountResponse receiveAmount(ReceiveAmountRequest request) {

        RespCollector collector = new RespCollector();

        CountDownLatch finishLatch = new CountDownLatch(quorum);

        for (ServerServiceGrpc.ServerServiceStub stub : this.stubs) {
            while (true) {
                try {
                    stub.withDeadlineAfter(3, TimeUnit.SECONDS).receiveAmount(request, new Observer<>(collector, finishLatch));
                    break;
                } catch (StatusRuntimeException e) {
                    if (e.getStatus().getCode() == Status.DEADLINE_EXCEEDED.getCode()){
                        System.out.println("Stub error");
                    }
                }
            }
        }

        try {
            finishLatch.await();
        } catch (InterruptedException e) {
            System.out.println("Error");
        }

        Iterator<Object> iterator = collector.responses.iterator();
        int counter = 0;
        int wid = -1;
        ReceiveAmountResponse bestResponse = null;

        synchronized (collector.responses) {
            while (iterator.hasNext()) {
                ReceiveAmountResponse response = (ReceiveAmountResponse) iterator.next();
                try {
                    PublicKey serverPubKey = crypto.getPubKeyGrpc(response.getPublicKey().toByteArray());
                    String finalString = serverPubKey.toString() + response.getMessage() + response.getWid();

                    if (!crypto.verifySignature(finalString, serverPubKey, response.getSignature().toByteArray())) {
                        iterator.remove();
                        counter++;
                    } else {
                        if (response.getWid() > wid){
                            wid = response.getWid();
                            bestResponse = response;
                        }
                    }

                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    System.out.println("Something wrong with the algorithm!");
                }
            }
        }

        if (counter > this.byzantine) {
            return null;
        } else {
            return bestResponse;
        }
    }

    public AuditResponse audit(AuditRequest request) {

        proof();

        RespCollector collector = new RespCollector();
        CountDownLatch finishLatch = new CountDownLatch(quorum);

        int port = 8080;

        for (ServerServiceGrpc.ServerServiceStub stub : this.stubs) {

            byte [] challenge = proofs.get(port);
            byte [] concatenated = Bytes.concat(challenge, request.getMyPublicKey().toByteArray());
            long pow = crypto.generateProofOfWork(concatenated);

            AuditRequest auditRequest = AuditRequest.newBuilder()
                    .setPublicKey(request.getPublicKey())
                    .setMyPublicKey(request.getMyPublicKey())
                    .setNonce(request.getNonce())
                    .setRid(request.getRid())
                    .setPow(pow)
                    .setConcatenated(ByteString.copyFrom(concatenated))
                    .setSignature(request.getSignature())
                    .build();
            while (true) {
                try {
                    stub.withDeadlineAfter(3, TimeUnit.SECONDS).audit(auditRequest, new Observer<>(collector, finishLatch));
                    break;
                } catch (StatusRuntimeException e) {
                    if (e.getStatus().getCode() == Status.DEADLINE_EXCEEDED.getCode()){
                        System.out.println("Stub error");
                    }
                }
            }
            port++;
        }

        try {
            finishLatch.await();
        } catch (InterruptedException e) {
            System.out.println("Error");
        }

        Iterator<Object> iterator = collector.responses.iterator();
        int counter = 0;
        AuditResponse bestResponse = null;
        int size = -1;

        synchronized (collector.responses) {
            while (iterator.hasNext()) {
                boolean fakeTransaction = false;
                AuditResponse response = (AuditResponse) iterator.next();
                try {
                    PublicKey serverPubKey = crypto.getPubKeyGrpc(response.getPublicKey().toByteArray());
                    String finalString = serverPubKey.toString() + response.getTransactionsList() + response.getNonce() + response.getRid() + response.getMessage();

                    if (!crypto.verifySignature(finalString, serverPubKey, response.getSignature().toByteArray()) || request.getNonce() + 1 != response.getNonce()
                            || request.getRid() != response.getRid()) {

                        iterator.remove();
                        counter++;

                    } else {
                        for (Transaction transaction : response.getTransactionsList()){
                            String transactionString = transaction.getSourceUsername() + transaction.getDestUsername()
                                    + transaction.getAmount() + crypto.getPubKeyGrpc(transaction.getSource().toByteArray())
                                    + crypto.getPubKeyGrpc(transaction.getDestination().toByteArray()) + transaction.getWid();

                            PublicKey transactionPubK = crypto.getPubKeyGrpc(request.getPublicKey().toByteArray());
                            if (!crypto.verifySignature(transactionString, transactionPubK, transaction.getSignature().toByteArray())) {
                                fakeTransaction = true;
                                break;
                            }
                        }

                        if (fakeTransaction) {
                            iterator.remove();
                            counter++;

                        } else {
                            if (response.getTransactionsList().size() > size) {
                                size = response.getTransactionsList().size();
                                bestResponse = response;
                            }
                        }
                    }

                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    System.out.println("Something wrong with the algorithm!");
                }
            }
        }

        if (counter > this.byzantine) {
            return null;
        } else {
            return bestResponse;
        }
    }

    public CheckWriteBackResponse checkWriteBack(CheckWriteBackRequest request) {

        RespCollector collector = new RespCollector();
        CountDownLatch finishLatch = new CountDownLatch(quorum);

        for (ServerServiceGrpc.ServerServiceStub stub : this.stubs) {
            stub.withDeadlineAfter(3, TimeUnit.SECONDS).checkWriteBack(request, new Observer<>(collector, finishLatch));
        }

        try {
            finishLatch.await();
        } catch (InterruptedException e) {
            System.out.println("Error");
        }

        Iterator<Object> iterator = collector.responses.iterator();
        int counter = 0;

        synchronized (collector.responses) {
            while (iterator.hasNext()) {
                CheckWriteBackResponse response = (CheckWriteBackResponse) iterator.next();
                try {
                    PublicKey serverPubKey = crypto.getPubKeyGrpc(response.getPublicKey().toByteArray());
                    String finalString = serverPubKey.toString() + response.getMessage();

                    if (!crypto.verifySignature(finalString, serverPubKey, response.getSignature().toByteArray())) {
                        iterator.remove();
                        counter++;
                    }
                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    System.out.println("Something wrong with the algorithm!");
                }
            }
        }

        if (counter > this.byzantine) {
            return null;
        } else {
            return (CheckWriteBackResponse) collector.responses.get(0);
        }
    }

    public AuditWriteBackResponse auditWriteBack(AuditWriteBackRequest request) {

        RespCollector collector = new RespCollector();
        CountDownLatch finishLatch = new CountDownLatch(quorum);

        for (ServerServiceGrpc.ServerServiceStub stub : this.stubs) {
            stub.withDeadlineAfter(3, TimeUnit.SECONDS).auditWriteBack(request, new Observer<>(collector, finishLatch));
        }

        try {
            finishLatch.await();
        } catch (InterruptedException e) {
            System.out.println("Error");
        }

        Iterator<Object> iterator = collector.responses.iterator();
        int counter = 0;

        synchronized (collector.responses) {
            while (iterator.hasNext()) {
                AuditWriteBackResponse response = (AuditWriteBackResponse) iterator.next();
                try {
                    PublicKey serverPubKey = crypto.getPubKeyGrpc(response.getPublicKey().toByteArray());
                    String finalString = serverPubKey.toString() + response.getMessage();

                    if (!crypto.verifySignature(finalString, serverPubKey, response.getSignature().toByteArray())) {
                        iterator.remove();
                        counter++;
                    }
                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    System.out.println("Something wrong with the algorithm!");
                }
            }
        }

        if (counter > this.byzantine) {
            return null;
        } else {
            return (AuditWriteBackResponse) collector.responses.get(0);
        }
    }

    @Override
    public final void close() {
        this.channels.forEach(ManagedChannel::shutdown);
    }
}