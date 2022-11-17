package pt.tecnico.bank;

import com.google.common.primitives.Bytes;
import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import pt.tecnico.bank.domain.Client;
import pt.tecnico.bank.domain.Transactions;
import pt.tecnico.bank.grpc.*;

import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static io.grpc.Status.INVALID_ARGUMENT;
import static pt.tecnico.bank.ServerMain.*;


public class ServerServiceImpl extends ServerServiceGrpc.ServerServiceImplBase {

    private ADEBInstanceManager adebInstanceManager;
    private ADEB adeb;

    public ServerServiceImpl(ADEB adeb, ADEBInstanceManager adebInstanceManager){
        this.adebInstanceManager = adebInstanceManager;
        this.adeb = adeb;
    }


    public void rid(RidRequest request, StreamObserver<RidResponse> responseObserver){
        String message = "";
        int rid = 0;

        try {
            PublicKey publicKey = crypto.getPubKeyGrpc(request.getPublicKey().toByteArray());
            rid = clientList.get(publicKey).getRid();
            message = "valid";
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            message = "Something wrong with the keys!";
        }

        String finalString = keyPair.getPublic().toString() + rid + message;
        byte[] signature = crypto.getSignature(finalString, keyPair.getPrivate());

        RidResponse response = RidResponse.newBuilder()
                .setServerPubKey(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .setRid(rid)
                .setMessage(message)
                .setSignature(ByteString.copyFrom(signature))
                .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    public void ping(PingRequest request, StreamObserver<PingResponse> responseObserver) {
        String input = request.getInput();

        if (input.isBlank()) {
            responseObserver.onError(INVALID_ARGUMENT.withDescription("Input cannot be empty!").asRuntimeException());
            return;
        }

        String output = input + "Pong";
        PingResponse response = PingResponse.newBuilder().setOutput(output).build();
        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    public void proof(ProofOfWorkRequest request, StreamObserver<ProofOfWorkResponse> responseObserver) {

        int nonce = request.getNonce();
        String message = "";
        byte [] bytes = new byte[256];

        try {
            PublicKey myPublicKey = crypto.getPubKeyGrpc(request.getPublicKey().toByteArray());

            String proofSignString = nonce + myPublicKey.toString();

            if (crypto.verifySignature(proofSignString, myPublicKey, request.getSignature().toByteArray())){

                SecureRandom secureRandom = new SecureRandom();
                secureRandom.nextBytes(bytes);

                clientList.get(myPublicKey).setChallenge(Bytes.concat(bytes, request.getPublicKey().toByteArray()));

                nonce++;
                message = "valid";

            } else {
                message = "Incorrect signature.";
            }

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            message = "Something wrong with the keys!";
        }

        String finalString = nonce + Arrays.toString(bytes) + keyPair.getPublic().toString() + message + port;
        byte [] signature = crypto.getSignature(finalString, keyPair.getPrivate());

        ProofOfWorkResponse response = ProofOfWorkResponse.newBuilder()
                .setNonce(nonce)
                .setChallenge(ByteString.copyFrom(bytes))
                .setServerPubkey(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .setMessage(message)
                .setPort(port)
                .setSignature(ByteString.copyFrom(signature))
                .build();
        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    public void openAccount(OpenAccountRequest request, StreamObserver<OpenAccountResponse> responseObserver) {
        String message = "";

        try {
            PublicKey publicKey = crypto.getPubKeyGrpc(request.getPublicKey().toByteArray());
            String username = request.getUsername();
            int wid = request.getWid();
            int balance = request.getBalance();
            byte [] pair_signature = request.getPairSign().toByteArray();

            String finalString1 = publicKey.toString() + username + wid + balance + Arrays.toString(pair_signature);
            if (crypto.verifySignature(finalString1, publicKey, request.getSignature().toByteArray())) {

                message = "valid";
                clientList.put(publicKey, new Client(username, pair_signature));
                saveHandler.saveState();

            } else {
                message = "Incorrect signature.";
            }

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            message = "Something wrong with the keys!";
        }

        String finalString = keyPair.getPublic().toString() + message;
        byte[] signature = crypto.getSignature(finalString, keyPair.getPrivate());

        OpenAccountResponse response = OpenAccountResponse.newBuilder()
                .setMessage(message)
                .setSignature(ByteString.copyFrom(signature))
                .setPublicKey(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    public void checkAccount(CheckAccountRequest request, StreamObserver<CheckAccountResponse> responseObserver) {

        int balance = 0;
        int wid = 0;

        String message = "";
        List<Transaction> transactions = new ArrayList<>();
        int rid = request.getRid();
        int nonce = request.getNonce();
        byte [] pairSignature = new byte[0];
        byte [] signature1 = request.getSignature().toByteArray();

        try {

            PublicKey publicKey = crypto.getPubKeyGrpc(request.getPublicKey().toByteArray());
            PublicKey mypublicKey = crypto.getPubKeyGrpc(request.getMyPublicKey().toByteArray());

            String finalString = publicKey.toString() + mypublicKey.toString() + rid + nonce;

            if (crypto.verifySignature(finalString, mypublicKey, signature1)) {

                if (clientList.containsKey(publicKey)) {

                    if (crypto.verifyProofOfWork(request.getConcatenated().toByteArray(), request.getPow()) && Arrays.equals(clientList.get(mypublicKey).getChallenge(), request.getConcatenated().toByteArray())) {

                        Client client = clientList.get(publicKey);
                        Client me = clientList.get(mypublicKey);

                        balance = client.getBalance();
                        wid = client.getWid();
                        pairSignature = client.getPair_signature();

                        if (!me.getEventList().contains(nonce)) {

                            me.addEvent(nonce);

                            for (Transactions transaction : client.getPending()) {
                                transactions.add(Transaction.newBuilder()
                                        .setSourceUsername(transaction.getSenderUsername())
                                        .setDestUsername(transaction.getDestUsername())
                                        .setAmount(transaction.getValue())
                                        .setSource(ByteString.copyFrom(transaction.getSourceKey().getEncoded()))
                                        .setDestination(ByteString.copyFrom(transaction.getDestKey().getEncoded()))
                                        .setWid(transaction.getWid())
                                        .setSignature(ByteString.copyFrom(transaction.getSignature()))
                                        .build());
                            }

                            me.setRid(rid);

                            saveHandler.saveState();

                            message = "valid";

                        } else {
                            message = "Replay attack!";
                        }
                    } else {
                        message = "No proof of work or wrong challenge!";
                    }
                } else {
                    message = "No account found with that username.";
                }
            } else {
                message = "Wrong signing from user!";
            }

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            message = "Something wrong with the keys!";
        }

        int nonce1 = nonce + 1;

        String finalString = keyPair.getPublic().toString() + balance + wid + Arrays.toString(pairSignature) + rid + message + transactions + nonce1;
        byte[] signature = crypto.getSignature(finalString, keyPair.getPrivate());

        CheckAccountResponse response = CheckAccountResponse.newBuilder()
                .setPublicKey(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .setBalance(balance)
                .setWid(wid)
                .setPairSign(ByteString.copyFrom(pairSignature))
                .setRid(rid)
                .setMessage(message)
                .addAllTransactions(transactions)
                .setNonce(nonce1)
                .setSignature(ByteString.copyFrom(signature))
                .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    public void sendAmount(SendAmountRequest request, StreamObserver<SendAmountResponse> responseObserver) {

        String message = "";
        Transaction transaction = request.getTransaction();

        String sourceUsername = transaction.getSourceUsername();
        String destUsername = transaction.getDestUsername();
        int amount = transaction.getAmount();
        byte [] transactionSignature = transaction.getSignature().toByteArray();

        int new_balance = request.getNewBalance();
        int wid = transaction.getWid();
        byte [] pairSign = request.getPairSign().toByteArray();

        try {
            PublicKey keySender = crypto.getPubKeyGrpc(transaction.getSource().toByteArray());
            PublicKey keyReceiver = crypto.getPubKeyGrpc(transaction.getDestination().toByteArray());

            String finalString = sourceUsername + destUsername + amount
                    + keySender.toString() + keyReceiver.toString()
                    + Arrays.toString(transactionSignature) + wid + Arrays.toString(pairSign) + new_balance;

            byte [] signature = request.getSignature().toByteArray();

            Client clientSender = clientList.get(keySender);

            if (crypto.verifySignature(finalString, keySender, signature)) {

                if (clientSender.getWid() < wid) {
                    System.out.println("\nADEB STARTING SEND AMOUNT");
                    ADEBInstance instance = adebInstanceManager.getInstance(finalString);
                    adeb.echo(finalString);
                    instance.await();
                    System.out.println("ADEB finished!");

                    if (clientSender.getWid() < wid && clientSender.getBalance() - amount == new_balance) {

                        Client clientReceiver = clientList.get(keyReceiver);

                        if (clientSender.getBalance() < amount) {
                            message = "Sender account does not have enough balance.";
                        } else if (0 >= amount) {
                            message = "Invalid amount, must be > 0.";
                        } else {

                            message = "valid";

                            clientReceiver.addPending(new Transactions(sourceUsername, destUsername, amount, keySender, keyReceiver, wid, transactionSignature));
                            clientSender.addHistory(new Transactions(sourceUsername, destUsername, amount, keySender, keyReceiver, wid, transactionSignature));

                            clientSender.setBalance(new_balance);
                            clientSender.setWid(wid);
                            clientSender.setPairSign(pairSign);

                            saveHandler.saveState();
                        }
                    } else {
                        message = "Wrong balance or wid.";
                    }
                } else {
                    message = "Replay attack!";
                }
            } else {
                message = "Incorrect signature or incorrect transaction id.";
            }

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            message = "Something wrong with the keys!";
        }

        String finalString1 = keyPair.getPublic().toString() + message + wid;
        byte [] signature1 = crypto.getSignature(finalString1, keyPair.getPrivate());

        SendAmountResponse response = SendAmountResponse.newBuilder()
                .setMessage(message)
                .setWid(wid)
                .setPublicKey(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .setSignature(ByteString.copyFrom(signature1))
                .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    public void receiveAmount(ReceiveAmountRequest request, StreamObserver<ReceiveAmountResponse> responseObserver) {

        String message = "";
        int transfer = request.getTransfer();
        int wid = request.getWid();
        int new_balance = request.getFutureBalance();
        byte [] pairSign = request.getPairSign().toByteArray();
        Transaction toAuditTransaction = request.getToAuditTransaction();

        try {
            PublicKey publicKey = crypto.getPubKeyGrpc(request.getPublicKey().toByteArray());
            String finalString = publicKey.toString() + new_balance + wid + Arrays.toString(pairSign) + transfer + toAuditTransaction;

            Client client = clientList.get(publicKey);

            if (crypto.verifySignature(finalString, publicKey, request.getSignature().toByteArray())) {

                if (client.getWid() < wid) {
                    System.out.println("\nADEB STARTING RECEIVE AMOUNT");
                    ADEBInstance instance = adebInstanceManager.getInstance(finalString);
                    adeb.echo(finalString);
                    instance.await();
                    System.out.println("ADEB finished!");

                    Transactions transaction = client.getPending().get(transfer);

                    if (client.getWid() < wid && transfer + 1 <= client.getPending().size() && transaction.getValue() + client.getBalance() == new_balance) {
                        message = "valid";

                        client.setBalance(new_balance);

                        client.removePending(transfer);
                        client.addHistory(new Transactions(toAuditTransaction.getSourceUsername(),
                                toAuditTransaction.getDestUsername(), toAuditTransaction.getAmount(),
                                crypto.getPubKeyGrpc(toAuditTransaction.getSource().toByteArray()),
                                crypto.getPubKeyGrpc(toAuditTransaction.getDestination().toByteArray()),
                                toAuditTransaction.getWid(), toAuditTransaction.getSignature().toByteArray()));

                        client.setWid(wid);
                        client.setPairSign(pairSign);

                        saveHandler.saveState();
                    }
                } else {
                    message = "Replay attack!";
                }

            } else {
                message = "Incorrect signature, repeated event or incorrect transaction id.";
            }

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            message = "Something wrong with the keys!";
        }

        String finalString1 = keyPair.getPublic().toString() + message + wid;
        byte [] signature1 = crypto.getSignature(finalString1, keyPair.getPrivate());

        ReceiveAmountResponse response = ReceiveAmountResponse.newBuilder()
                .setPublicKey(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .setWid(wid)
                .setMessage(message)
                .setSignature(ByteString.copyFrom(signature1))
                .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    public void audit(AuditRequest request, StreamObserver<AuditResponse> responseObserver) {

        String message = "";
        int nonce = request.getNonce();
        int rid = request.getRid();
        List<Transaction> transactions = new ArrayList<>();

        try {
            PublicKey publicKey = crypto.getPubKeyGrpc(request.getPublicKey().toByteArray());
            PublicKey mypublicKey = crypto.getPubKeyGrpc(request.getMyPublicKey().toByteArray());

            String finalString = publicKey.toString() + mypublicKey.toString() + nonce + rid;

            if (crypto.verifySignature(finalString, mypublicKey, request.getSignature().toByteArray())) {
                if (crypto.verifyProofOfWork(request.getConcatenated().toByteArray(), request.getPow()) && Arrays.equals(clientList.get(mypublicKey).getChallenge(), request.getConcatenated().toByteArray())) {
                    if (clientList.containsKey(publicKey)) {

                        Client client = clientList.get(publicKey);
                        Client me = clientList.get(mypublicKey);

                        if (!me.getEventList().contains(nonce)) {

                            me.addEvent(nonce);

                            for (Transactions transaction : client.getHistory()) {
                                transactions.add(Transaction.newBuilder()
                                        .setSourceUsername(transaction.getSenderUsername())
                                        .setDestUsername(transaction.getDestUsername())
                                        .setAmount(transaction.getValue())
                                        .setSource(ByteString.copyFrom(transaction.getSourceKey().getEncoded()))
                                        .setDestination(ByteString.copyFrom(transaction.getDestKey().getEncoded()))
                                        .setWid(transaction.getWid())
                                        .setSignature(ByteString.copyFrom(transaction.getSignature()))
                                        .build());
                            }

                            me.setRid(rid);

                            saveHandler.saveState();

                            message = "valid";

                        } else {
                            message = "Replay attack!";
                        }
                    } else {
                        message = "No account found with that username.";
                    }
                } else {
                    message = "No proof of work or wrong challenge!";
                }
            } else {
                message = "Wrong signing from user!";
            }

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            message = "Something wrong with the keys!";
        }

        int nonce1 = nonce + 1;

        String finalString = keyPair.getPublic().toString() + transactions + nonce1 + rid + message;
        byte[] signature = crypto.getSignature(finalString, keyPair.getPrivate());

        AuditResponse response = AuditResponse.newBuilder()
                .setPublicKey(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .addAllTransactions(transactions)
                .setNonce(nonce1)
                .setRid(rid)
                .setMessage(message)
                .setSignature(ByteString.copyFrom(signature))
                .build();
        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    public void checkWriteBack(CheckWriteBackRequest request, StreamObserver<CheckWriteBackResponse> responseObserver){
        String message = "";
        List<Transaction> transactions = request.getTransactionsList();
        int balance = request.getBalance();
        int wid = request.getWid();
        byte [] pairSign = request.getPairSign().toByteArray();
        try {
            PublicKey publicKey = crypto.getPubKeyGrpc(request.getPublicKey().toByteArray());
            PublicKey mypublicKey = crypto.getPubKeyGrpc(request.getMyPublicKey().toByteArray());
            String finalString = String.valueOf(balance) + transactions + wid + Arrays.toString(pairSign) + publicKey.toString() + mypublicKey.toString();

            if (crypto.verifySignature(finalString, mypublicKey, request.getSignature().toByteArray())) {

                System.out.println("\nADEB STARTING CHECK WRITE BACK");
                ADEBInstance instance = adebInstanceManager.getInstance(finalString);
                adeb.echo(finalString);
                instance.await();
                System.out.println("ADEB finished!");

                Client client = clientList.get(publicKey);
                List<Transactions> pending = new ArrayList<>();

                if (wid > client.getWid()) {
                    for (Transaction transaction : transactions) {
                        pending.add(new Transactions(transaction.getSourceUsername(), transaction.getDestUsername(), transaction.getAmount(),
                                crypto.getPubKeyGrpc(transaction.getSource().toByteArray()), crypto.getPubKeyGrpc(transaction.getDestination().toByteArray()),
                                transaction.getWid(), transaction.getSignature().toByteArray()));
                    }
                    client.setBalance(balance);
                    client.setPending(pending);
                    client.setWid(wid);
                    client.setPairSign(pairSign);
                }
                System.out.println("Successful write back!");
                message = "valid";
                saveHandler.saveState();

            } else {
                System.out.println("Not write back!");
            }

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            message = "Something wrong with the keys!";
        }

        String finalString = keyPair.getPublic().toString() + message;
        byte [] signature = crypto.getSignature(finalString, keyPair.getPrivate());

        CheckWriteBackResponse response = CheckWriteBackResponse.newBuilder().setMessage(message)
                .setPublicKey(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .setSignature(ByteString.copyFrom(signature))
                .build();
        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    public void auditWriteBack(AuditWriteBackRequest request, StreamObserver<AuditWriteBackResponse> responseObserver){
        String message = "";
        List<Transaction> transactions = request.getTransactionsList();
        try {
            PublicKey publicKey = crypto.getPubKeyGrpc(request.getPublicKey().toByteArray());
            PublicKey mypublicKey = crypto.getPubKeyGrpc(request.getMyPublicKey().toByteArray());
            String finalString = transactions + publicKey.toString() + mypublicKey.toString();

            if (crypto.verifySignature(finalString, mypublicKey, request.getSignature().toByteArray())) {

                System.out.println("\nADEB STARTING AUDIT WRITE BACK");
                ADEBInstance instance = adebInstanceManager.getInstance(finalString);
                adeb.echo(finalString);
                instance.await();
                System.out.println("ADEB finished!");

                Client client = clientList.get(publicKey);
                List<Transactions> history = new ArrayList<>();

                for (Transaction transaction : transactions) {
                    history.add(new Transactions(transaction.getSourceUsername(), transaction.getDestUsername(), transaction.getAmount(),
                            crypto.getPubKeyGrpc(transaction.getSource().toByteArray()), crypto.getPubKeyGrpc(transaction.getDestination().toByteArray()),
                            transaction.getWid(), transaction.getSignature().toByteArray()));
                }

                client.setHistory(history);

                System.out.println("Successful write back!");
                message = "valid";
                saveHandler.saveState();

            } else {
                System.out.println("Not write back!");
            }

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            message = "Something wrong with the keys!";
        }

        String finalString = keyPair.getPublic().toString() + message;
        byte [] signature = crypto.getSignature(finalString, keyPair.getPrivate());

        AuditWriteBackResponse response = AuditWriteBackResponse.newBuilder().setMessage(message)
                .setPublicKey(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .setSignature(ByteString.copyFrom(signature))
                .build();
        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }
}