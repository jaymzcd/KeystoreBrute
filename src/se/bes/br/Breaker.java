package se.bes.br;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;

public class Breaker {

    private static final Object PASS_LOCK = new Object();
    private volatile boolean mIsFound = false;
    private volatile long mCounter = 0;
    private char[] mFoundPassword = new char[0];

    private final WordlistReader mGenerator;
    private final PasswordTester[] mTesters;

    private volatile char[] globalPass = new char[0];

    private final Shutdown mShutdown = new Shutdown();

    /**
     * Will run when interrupting the program (Ctrl+C).
     * This allows us to print a newline before terminating.
     */
    private static class Shutdown extends Thread {
        private boolean keepOn = true;
        @Override
        public void run() {
            // Just print a newline to save the last line.
            System.out.println();
            keepOn = false;
        }

        public boolean keepOn() {
            return keepOn;
        }
    }

    /**
     * Sets up and initiates all the threads needed to break the given keystore.
     *
     * @param fileName
     *            The path and filename of the {@link KeyStore} you wish to
     *            break.
     * @param startDepth
     *            The number of characters to start trying at. A keystore
     *            requires 6 characters so that is probably a minimum, but any
     *            value is acceptable.
     * @param threads
     *            The number of {@link Thread}s you wish to have simultaneously
     *            running, breaking passwords. Experiment to find the optimal
     *            value for your setup.
     */
    public Breaker(String fileName, String path) {
        mGenerator = new WordlistReader(path);

        mTesters = new PasswordTester[1];
        for (int i = 0; i < mTesters.length; i++) {
            mTesters[i] = new PasswordTester(fileName);
            mTesters[i].start();
        }

    }

    /**
     * This method will block until the {@link KeyStore} password is
     * found, at which point it will return the password as a {@link String}.
     * <br/>
     * May take a <b>VERY</b> long time.
     * @return A {@link String} with the password used to open the given {@link KeyStore}
     */
    public String getPassphrase() throws InterruptedException {
        Runtime.getRuntime().addShutdownHook(mShutdown);
        System.out.println();
        long totalStartTime = System.currentTimeMillis();

        while (!mIsFound && mShutdown.keepOn()) {
            long startTime = System.currentTimeMillis();
            long startCount = mCounter;
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            long diffTime = System.currentTimeMillis() - startTime;
            long diffCount = mCounter - startCount;

            long rate = 0;
            if (diffTime > 0) {
                rate = diffCount * 1000 / diffTime;
            }

            long totalTime = (System.currentTimeMillis() - totalStartTime) / 1000;

            System.out.print("Tested " + mCounter
                    + " pws (" + totalTime + " s -- " + rate + " pw/s): "
                    + new String(globalPass) + "       \r");
        }

        return new String(mFoundPassword);
    }

    private class PasswordTester extends Thread {
        /**
         * The bytes of a {@link KeyStore} loaded into RAM.
         */
        private ByteArrayInputStream mStream;

        /**
         * Loads a {@link KeyStore} on file into a {@link ByteArrayInputStream}
         * for faster access.
         */
        public PasswordTester(String fileName) {
            try {
                File file = new File(fileName);

                FileInputStream fis = new FileInputStream(file);

                byte[] fileBytes = new byte[(int)file.length()];

                fis.read(fileBytes);

                mStream = new ByteArrayInputStream(fileBytes);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        /**
         * Gets a password from the list of passwords and tests if it
         * can be used to open the {@link KeyStore}.
         */
        @Override
        public void run() {
            KeyStore ks = null;
            try {
                ks = KeyStore.getInstance(KeyStore.getDefaultType());
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
            char[] passwd = null;
            boolean valid_word = true;

            while((!mIsFound)) {
                //System.out.println("Next pw");
                mStream.reset();
                try {
                    passwd = mGenerator.getNextPassword();
                    ks.load(mStream, passwd);
                } catch (Throwable t) {
                    continue;
                }

                mFoundPassword = passwd;
                mIsFound = true;
            }
        }
    }

    private class WordlistReader {
        private String path;
        private BufferedReader buffReader;

        public WordlistReader(String path) {
            this.path = path;
            openfile();
        }

        public void openfile() {
            try {
                FileReader fr = new FileReader(this.path);
                this.buffReader = new BufferedReader(fr);
            } catch(IOException e) {
                System.out.println("Cannot open file");
            }
        }

        public char[] getNextPassword() {
            String word;
            try {
                word = buffReader.readLine();
                System.out.println("Checking " + word);
                return word.toCharArray();
            } catch(IOException e) {
                System.out.println("NILL");
            }
            return null;
        }
    }

}
