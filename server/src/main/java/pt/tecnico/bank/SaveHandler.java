package pt.tecnico.bank;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.file.*;

import static pt.tecnico.bank.ServerMain.clientList;

public class SaveHandler {

    private String serverName;

    public SaveHandler(String serverName){
        this.serverName = serverName;
    }

    public void saveState() throws IOException {

        byte[] clientListBytes = mapToBytes();

        Path tmpPath = Paths.get(System.getProperty("user.dir"), this.serverName);
        Path tmpPathFile = File.createTempFile("atomic", "tmp", new File(tmpPath.toString())).toPath();
        Files.write(tmpPathFile, clientListBytes, StandardOpenOption.APPEND);

        Files.move(tmpPathFile, Paths.get(System.getProperty("user.dir"), this.serverName, "db.txt"), StandardCopyOption.ATOMIC_MOVE);

    }

    private byte[] mapToBytes() throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(byteOut);
        out.writeObject(clientList);
        byte[] clientListBytes = byteOut.toByteArray();
        out.flush();
        byteOut.close();
        return clientListBytes;
    }
}
