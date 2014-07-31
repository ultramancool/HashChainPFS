package experimental.hashchainpfs;

import com.google.common.io.ByteStreams;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Hex;
import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import java.io.*;

/**
 * The HashChainPFS command line tool.
 */
public class Main {
    HashChainForwardSecrecy hashChainForwardSecrecy;
    @Argument(required = true, index = 0, usage = "the mode of operation", metaVar = "mode")
    RunMode mode;
    @Argument(required = true, index = 1, usage = "the file from which to save/load the key", metaVar = "filename")
    String fileName;
    @Option(name = "-key", usage = "The 256-bit hex key to be used for setup. Will be generated if not present.")
    String key;

    public static void main(String[] args) {
        Main bean = new Main();
        CmdLineParser parser = new CmdLineParser(bean);
        try {
            parser.parseArgument(args);
            System.exit(bean.run());
        } catch (CmdLineException e) {
            // handling of wrong arguments
            System.err.println(e.getMessage());
            parser.printUsage(System.err);
        }
    }

    public int run() {
        if (mode == RunMode.SETUP) {
            if (key == null || key.isEmpty()) {
                hashChainForwardSecrecy = new HashChainForwardSecrecy();
            } else {
                hashChainForwardSecrecy = new HashChainForwardSecrecy(Hex.decode(key));
            }
            if (!save())
                return 1;
            System.out.println("Setup successful. Key is:");
            System.out.println(Hex.toHexString(hashChainForwardSecrecy.getCurrentKey()));
            return 0;
        }

        load();
        if (hashChainForwardSecrecy == null)
            return 1;

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            ByteStreams.copy(System.in, byteArrayOutputStream);
        } catch (IOException e) {
            System.err.println("Error reading from stdin");
            e.printStackTrace();
            return 1;
        }

        try {
            byte[] output;
            if (mode == RunMode.DECRYPT) {
                output = hashChainForwardSecrecy.decryptMessage(byteArrayOutputStream.toByteArray());
            } else {
                output = hashChainForwardSecrecy.encryptMessage(byteArrayOutputStream.toByteArray());
            }
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(output);
            ByteStreams.copy(byteArrayInputStream, System.out);
        } catch (InvalidCipherTextException e) {
            System.err.println("Invalid ciphertext. Possible attack or error in transmission.");
            e.printStackTrace();
            return 1;
        } catch (IOException e) {
            System.err.println("IO error writing output");
            e.printStackTrace();
            return 1;
        }

        hashChainForwardSecrecy.advance();
        save();
        return 0;
    }

    public void load() {
        try {
            ObjectInputStream in = new ObjectInputStream(new FileInputStream(fileName));
            hashChainForwardSecrecy = (HashChainForwardSecrecy) in.readObject();
        } catch (IOException e) {
            System.err.println("Error doing file I/O");
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            System.err.println("Error loading key");
            e.printStackTrace();
        }
    }

    public boolean save() {
        try {
            ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(fileName));
            out.writeObject(hashChainForwardSecrecy);
        } catch (IOException e) {
            System.err.println("Error doing file I/O");
            e.printStackTrace();
            return false;
        }
        return true;
    }

    enum RunMode {
        DECRYPT,
        ENCRYPT,
        SETUP
    }
}
