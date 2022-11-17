# Demo

Group 26 - Bernardo Quinteiro 93692, Diogo Lopes 93700, Gonçalo Mateus 93713

## 1. System setup

### 1.1. Compile the project

First, we need to compile and install all the modules and respective dependencies.
To do it, just go to the *HighlyDependableSystems* directory and run the following command:

```sh
$ mvn clean install -DskipTests
```

### 1.2. Start the *server*

Next, we need to start the servers.
To do it, just go to the *server* directory and run the following command with the desired byzantine servers:

```sh
$ startServers.bat 1
```

This will initialize 3*1+1=4 servers.

##### 1.2.1 Run *server* tests
To run the server tests go to the *server-tester* directory and run the command:

```sh
$ mvn verify 
```
(This will run the tests for 1 byzantine fault, so 4 running servers)

### 1.3. Start the *Client*

To start the *app* we need to go inside the *client* directory and run the following command according to the before selected byzantine servers:

 ```sh
$ startClient.bat 1
```



## 2. Commands Test

In this section we will run every command in order to test every system operation.
Each subsection regards each app operation. 
There are two phases. The login phase and the operations phase.

**Let's start with the login phase:**

### 2.1. *Open Account*

This command asks for a username and a password (at least 6 characters long), and creates an user with those credentials.

```sh
Choose your account username: goncalo
Choose your account password: password1

Account created successfully with username: goncalo
```

### 2.2. *Load Account*

This command asks for the credentials of a created user and loads into his account.

```sh
Account username: goncalo
Account password: password1

Successfully logged in.
```

### 2.3. *Quit*

This command exits the app and closes the frontend.



**Now, passing to the operations phase:**

### 2.4 *Check account*

This command receives a username of an account and returns not only the available balance but also the list of pending transactions.

```sh
Account username: goncalo

Available Balance: 500

No pending transactions.
```


### 2.5 *Send Amount*

This command allows the logged user to send a certain amount to another account. It receives the username of the receiver and the ballance we want to send. In the end, it adds the transaction to the receiver pending list.

```sh
Receiver username: goncalo
Amount: 100

Pending transaction, waiting for approval.
```

```sh
Account username: goncalo

Available Balance: 500

Pending Transactions:
1) 100 from diogo
```

### 2.6. *Receive Amount*

This command allows us to accept one transaction from the pending list by asking the ID of it.

```sh
Transaction number: 1

Transaction Accepted.
```


### 2.7 *Audit*

This command receives a username and returns the transaction history of that account.

```sh
Account username: goncalo

History:
100 from diogo
```
```sh
Account username: diogo

History:
100 to goncalo
```

### 2.8. *Ping*

 This command simply returns a PingPong.


### 2.9. *Logout*

This command logs out from the current account and returns to the Open/Load menu.











