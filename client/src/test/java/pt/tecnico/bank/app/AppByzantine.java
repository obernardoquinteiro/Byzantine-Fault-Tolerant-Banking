package pt.tecnico.bank.app;

import com.google.protobuf.ByteString;
import pt.tecnico.bank.Crypto;
import pt.tecnico.bank.grpc.*;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;

public class AppByzantine {

    ByzantineClientFrontend frontend;
    Crypto crypto;
    int balance;
    int rid;

    public AppByzantine(ByzantineClientFrontend frontend, Crypto crypto) {
        this.frontend = frontend;
        this.crypto = crypto;
        this.balance = 500;
        this.rid = 0;
    }

    // App methods that send requests to the ServerServiceImpl and returns responses to the user

    public CheckAccountResponse checkAccount(PublicKey publicKey, KeyPair keyPair){

        int nonce = crypto.getSecureRandom();

        int new_rid = this.rid + 1;

        String finalString = publicKey.toString() + keyPair.getPublic().toString() + new_rid + nonce;
        byte [] signature = crypto.getSignature(finalString, keyPair.getPrivate());

        CheckAccountRequest request = CheckAccountRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                .setMyPublicKey(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .setRid(this.rid + 1)
                .setNonce(nonce)
                .setSignature(ByteString.copyFrom(signature))
                .build();

        CheckAccountResponse response = frontend.checkAccountManIntheMiddle(request);

        if (response == null) {
            System.out.println("No quorum achieved!");
            return response;
        }
        else if (response.getMessage().equals("valid")) {

            this.rid++;
            List<Transaction> pending = response.getTransactionsList();

            if (pending.isEmpty()) {
                System.out.println("\nAvailable Balance: " + response.getBalance() + "\n\nNo pending transactions.\n");
            } else {
                System.out.println("\nAvailable Balance: " + response.getBalance() + "\n\nPending Transactions:");
                int i = 1;
                for (Transaction transaction : pending) {
                    System.out.println(i + ") " + transaction.getAmount() + " from " + transaction.getSourceUsername());
                    i++;
                }
                System.out.println();
            }
            return response;

        } else {
            System.out.println(response.getMessage());
            return response;
        }
    }

    public CheckAccountResponse checkAccount2(PublicKey publicKey, KeyPair keyPair){

        int nonce = crypto.getSecureRandom();

        int new_rid = this.rid + 1;

        String finalString = publicKey.toString() + keyPair.getPublic().toString() + new_rid + nonce;
        byte [] signature = crypto.getSignature(finalString, keyPair.getPrivate());

        CheckAccountRequest request = CheckAccountRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                .setMyPublicKey(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .setRid(this.rid + 1)
                .setNonce(nonce)
                .setSignature(ByteString.copyFrom(signature))
                .build();

        CheckAccountResponse response = frontend.checkAccountOneByzantine(request);

        if (response == null) {
            System.out.println("No quorum achieved!");
            return response;
        }
        else if (response.getMessage().equals("valid")) {

            this.rid++;
            List<Transaction> pending = response.getTransactionsList();

            if (pending.isEmpty()) {
                System.out.println("\nAvailable Balance: " + response.getBalance() + "\n\nNo pending transactions.\n");
            } else {
                System.out.println("\nAvailable Balance: " + response.getBalance() + "\n\nPending Transactions:");
                int i = 1;
                for (Transaction transaction : pending) {
                    System.out.println(i + ") " + transaction.getAmount() + " from " + transaction.getSourceUsername());
                    i++;
                }
                System.out.println();
            }
            return response;

        } else {
            System.out.println(response.getMessage());
            return response;
        }
    }

    public CheckAccountResponse checkAccount3(PublicKey publicKey, KeyPair keyPair){

        int nonce = crypto.getSecureRandom();

        int new_rid = this.rid + 1;

        String finalString = publicKey.toString() + keyPair.getPublic().toString() + new_rid + nonce;
        byte [] signature = crypto.getSignature(finalString, keyPair.getPrivate());

        CheckAccountRequest request = CheckAccountRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                .setMyPublicKey(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .setRid(this.rid + 1)
                .setNonce(nonce)
                .setSignature(ByteString.copyFrom(signature))
                .build();

        CheckAccountResponse response = frontend.checkAccountTwoByzantine(request);

        if (response == null) {
            System.out.println("No quorum achieved!");
            return response;
        }
        else if (response.getMessage().equals("valid")) {

            this.rid++;
            List<Transaction> pending = response.getTransactionsList();

            if (pending.isEmpty()) {
                System.out.println("\nAvailable Balance: " + response.getBalance() + "\n\nNo pending transactions.\n");
            } else {
                System.out.println("\nAvailable Balance: " + response.getBalance() + "\n\nPending Transactions:");
                int i = 1;
                for (Transaction transaction : pending) {
                    System.out.println(i + ") " + transaction.getAmount() + " from " + transaction.getSourceUsername());
                    i++;
                }
                System.out.println();
            }
            return response;

        } else {
            System.out.println(response.getMessage());
            return response;
        }
    }

    /*public SendAmountResponse sendAmount(PublicKey senderPubK, PublicKey receiverPubK, int amount, PrivateKey senderPrivK, String sourceUsername, String destUsername) {

        int nonce = crypto.getSecureRandom();

        int new_rid = this.rid + 1;

        String finalString1 = senderPubK.toString() + senderPubK.toString() + new_rid + nonce;
        byte [] signature1 = crypto.getSignature(finalString1, senderPrivK);

        CheckAccountResponse response1 = frontend.checkAccount(CheckAccountRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(senderPubK.getEncoded()))
                .setMyPublicKey(ByteString.copyFrom(senderPubK.getEncoded()))
                .setRid(this.rid + 1)
                .setNonce(nonce)
                .setSignature(ByteString.copyFrom(signature1))
                .build());

        if (response1 == null) {
            System.out.println("No quorum achieved!");
            return null;
        }
        else if (response1.getMessage().equals("valid")) {

            this.rid++;

            int new_wid = response1.getWid() + 1;
            int new_balance = response1.getBalance() - amount;

            String transactionString = sourceUsername + destUsername + amount + senderPubK.toString() + receiverPubK.toString() + new_wid;
            byte[] signatureTrans = crypto.getSignature(transactionString, senderPrivK);
            Transaction transaction = Transaction.newBuilder()
                    .setSourceUsername(sourceUsername)
                    .setDestUsername(destUsername)
                    .setAmount(amount)
                    .setSource(ByteString.copyFrom(senderPubK.getEncoded()))
                    .setDestination(ByteString.copyFrom(receiverPubK.getEncoded()))
                    .setWid(new_wid)
                    .setSignature(ByteString.copyFrom(signatureTrans))
                    .build();

            String pairSignatureString = String.valueOf(new_balance) + new_wid;
            byte[] pairSignature = crypto.getSignature(pairSignatureString, senderPrivK);

            String finalString = sourceUsername + destUsername + amount
                    + senderPubK + receiverPubK + Arrays.toString(signatureTrans)
                    + new_wid + Arrays.toString(pairSignature) + new_balance;

            byte[] signature = crypto.getSignature(finalString, senderPrivK);

            SendAmountRequest request = SendAmountRequest.newBuilder()
                    .setTransaction(transaction)
                    .setNewBalance(new_balance)
                    .setPairSign(ByteString.copyFrom(pairSignature))
                    .setSignature(ByteString.copyFrom(signature))
                    .build();

            SendAmountResponse response = frontend.sendAmount(request);

            if (response == null) {
                System.out.println("No quorum achieved!");
                return response;
            } else if (response.getMessage().equals("valid")) {
                System.out.println("\nPending transaction, waiting for approval.\n");
                return response;
            } else {
                System.out.println(response.getMessage());
                return response;
            }
        } else {
            System.out.println(response1.getMessage());
            return null;
        }
    }

    public ReceiveAmountResponse receiveAmount(PublicKey publicKey, int transfer, PrivateKey privateKey) {

        int nonce = crypto.getSecureRandom();

        int new_rid = this.rid + 1;

        String finalString1 = publicKey.toString() + publicKey.toString() + new_rid + nonce;
        byte [] signature1 = crypto.getSignature(finalString1, privateKey);

        CheckAccountResponse response1 = frontend.checkAccount(CheckAccountRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                .setMyPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                .setRid(this.rid + 1)
                .setNonce(nonce)
                .setSignature(ByteString.copyFrom(signature1))
                .build());

        if (response1 == null) {
            System.out.println("No quorum achieved!");
            return null;
        }
        else if (response1.getMessage().equals("valid")) {
            try {
                Transaction auxTransaction = response1.getTransactions(transfer);
                int future_balance = response1.getBalance() + auxTransaction.getAmount();

                this.rid++;

                int new_wid = response1.getWid() + 1;
                String pairSignString = String.valueOf(future_balance) + new_wid;
                byte[] pairSign = crypto.getSignature(pairSignString, privateKey);

                try {

                    PublicKey sourceKey = crypto.getPubKeyGrpc(auxTransaction.getSource().toByteArray());
                    PublicKey destKey = crypto.getPubKeyGrpc(auxTransaction.getDestination().toByteArray());
                    String transactionString = auxTransaction.getSourceUsername() + auxTransaction.getDestUsername()
                            + auxTransaction.getAmount() + sourceKey.toString() + destKey.toString() + new_wid;

                    byte[] signatureTrans = crypto.getSignature(transactionString, privateKey);

                    Transaction toAuditTransaction = Transaction.newBuilder()
                            .setSourceUsername(auxTransaction.getSourceUsername())
                            .setDestUsername(auxTransaction.getDestUsername())
                            .setAmount(auxTransaction.getAmount())
                            .setSource(ByteString.copyFrom(sourceKey.getEncoded()))
                            .setDestination(ByteString.copyFrom(destKey.getEncoded()))
                            .setWid(new_wid)
                            .setSignature(ByteString.copyFrom(signatureTrans))
                            .build();

                    byte[] signature = crypto.getSignature(publicKey.toString() + future_balance + new_wid + Arrays.toString(pairSign) + transfer + toAuditTransaction, privateKey);

                    ReceiveAmountRequest request = ReceiveAmountRequest.newBuilder()
                            .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                            .setFutureBalance(future_balance)
                            .setWid(new_wid)
                            .setPairSign(ByteString.copyFrom(pairSign))
                            .setTransfer(transfer)
                            .setToAuditTransaction(toAuditTransaction)
                            .setSignature(ByteString.copyFrom(signature))
                            .build();

                    ReceiveAmountResponse response = frontend.receiveAmount(request);

                    if (response == null) {
                        System.out.println("No quorum achieved!");
                        return response;
                    } else if (response.getMessage().equals("valid")) {
                        System.out.println("\nTransaction Accepted.\n");
                        return response;
                    } else {
                        System.out.println("\n" + response.getMessage());
                        return response;
                    }
                } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                    System.out.println("Something went wrong while getting keys...");
                    return null;
                }
            } catch (IndexOutOfBoundsException e) {
                System.out.println("Invalid transaction id.");
                return null;
            }
        } else {
            System.out.println(response1.getMessage());
            return null;
        }
    }*/

    public AuditResponse audit(PublicKey publicKey, KeyPair keyPair, String username){

        int random = crypto.getSecureRandom();

        int new_rid = this.rid + 1;

        String finalString = publicKey.toString() + keyPair.getPublic().toString() + random + new_rid;
        byte [] signature = crypto.getSignature(finalString, keyPair.getPrivate());

        AuditRequest request = AuditRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                .setMyPublicKey(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .setNonce(random)
                .setRid(this.rid + 1)
                .setSignature(ByteString.copyFrom(signature))
                .build();

        AuditResponse response = frontend.auditManIntheMiddle(request);

        if (response == null) {
            System.out.println("No quorum achieved!");
            return null;
        } else if (response.getMessage().equals("valid")) {
            this.rid++;
            List<Transaction> history = response.getTransactionsList();

            if (history.isEmpty()) {
                System.out.println("\nNo history to be shown.\n");
            } else {

                System.out.println("\nHistory:\n");

                for (Transaction transaction : history) {
                    if (transaction.getSourceUsername().equals(username)) {
                        System.out.println(transaction.getAmount() + " to " + transaction.getDestUsername());
                    } else {
                        System.out.println(transaction.getAmount() + " from " + transaction.getSourceUsername());
                    }
                }
                System.out.println();
            }

            return response;

        } else {
            System.out.println(response.getMessage());
            return response;
        }
    }

    public AuditResponse auditOneByzantine(PublicKey publicKey, KeyPair keyPair, String username){

        int random = crypto.getSecureRandom();

        int new_rid = this.rid + 1;

        String finalString = publicKey.toString() + keyPair.getPublic().toString() + random + new_rid;
        byte [] signature = crypto.getSignature(finalString, keyPair.getPrivate());

        AuditRequest request = AuditRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                .setMyPublicKey(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .setNonce(random)
                .setRid(this.rid + 1)
                .setSignature(ByteString.copyFrom(signature))
                .build();

        AuditResponse response = frontend.auditOneByzantine(request);

        if (response == null) {
            System.out.println("No quorum achieved!");
            return null;
        } else if (response.getMessage().equals("valid")) {
            this.rid++;
            List<Transaction> history = response.getTransactionsList();

            if (history.isEmpty()) {
                System.out.println("\nNo history to be shown.\n");
            } else {

                System.out.println("\nHistory:\n");

                for (Transaction transaction : history) {
                    if (transaction.getSourceUsername().equals(username)) {
                        System.out.println(transaction.getAmount() + " to " + transaction.getDestUsername());
                    } else {
                        System.out.println(transaction.getAmount() + " from " + transaction.getSourceUsername());
                    }
                }
                System.out.println();
            }

            return response;

        } else {
            System.out.println(response.getMessage());
            return response;
        }
    }

    public AuditResponse auditTwoByzantine(PublicKey publicKey, KeyPair keyPair, String username){

        int random = crypto.getSecureRandom();

        int new_rid = this.rid + 1;

        String finalString = publicKey.toString() + keyPair.getPublic().toString() + random + new_rid;
        byte [] signature = crypto.getSignature(finalString, keyPair.getPrivate());

        AuditRequest request = AuditRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                .setMyPublicKey(ByteString.copyFrom(keyPair.getPublic().getEncoded()))
                .setNonce(random)
                .setRid(this.rid + 1)
                .setSignature(ByteString.copyFrom(signature))
                .build();

        AuditResponse response = frontend.auditTwoByzantine(request);

        if (response == null) {
            System.out.println("No quorum achieved!");
            return null;
        } else if (response.getMessage().equals("valid")) {
            this.rid++;
            List<Transaction> history = response.getTransactionsList();

            if (history.isEmpty()) {
                System.out.println("\nNo history to be shown.\n");
            } else {

                System.out.println("\nHistory:\n");

                for (Transaction transaction : history) {
                    if (transaction.getSourceUsername().equals(username)) {
                        System.out.println(transaction.getAmount() + " to " + transaction.getDestUsername());
                    } else {
                        System.out.println(transaction.getAmount() + " from " + transaction.getSourceUsername());
                    }
                }
                System.out.println();
            }

            return response;

        } else {
            System.out.println(response.getMessage());
            return response;
        }
    }
}