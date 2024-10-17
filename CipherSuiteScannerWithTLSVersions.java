import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;

public class CipherSuiteScannerWithTLSVersions {

    private static final List<String> TLS_VERSIONS = Arrays.asList(
       "TLSv1", // TLS 1.0
            "TLSv1.1", // TLS 1.1
            "TLSv1.2", // TLS 1.2
            "TLSv1.3" // TLS 1.3
    );

    private static final int CONNECTION_TIMEOUT = 5000;
    private static final int THREAD_POOL_SIZE = 20;

    public static void main(String[] args) {
        System.out.println("Starting Cipher Suite Scanner with TLS Versions...\n");
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
        List<Future<EndpointResult>> futures = new ArrayList<>();

        for (String arg : args) {
            Endpoint endpoint = new Endpoint(arg, 443);
            Future<EndpointResult> fut1 = executor.submit(() -> scanEndpoint(endpoint));
            futures.add(fut1);
        }
        executor.shutdown();

        for (Future<EndpointResult> future : futures) {
            try {
                EndpointResult result = future.get();
                printEndpointResult(result);
            } catch (InterruptedException | ExecutionException e) {
                System.err.println("Error scanning endpoint: " + e.getMessage());
            }
        }

        System.out.println("Cipher Suite Scan with TLS Versions Completed.");
    }

    private static EndpointResult scanEndpoint(Endpoint endpoint) {
        Map<String, List<String>> tlsCipherMap = new ConcurrentHashMap<>();
        for (String tlsVersion : TLS_VERSIONS) {
            List<String> supportedCiphers = Collections.synchronizedList(new ArrayList<>());
            String[] cipherSuites = getCipherSuitesForTLSVersion(tlsVersion);

            if (cipherSuites.length == 0) {
                tlsCipherMap.put(tlsVersion, supportedCiphers);
                continue;
            }
            for (String cipher : cipherSuites) {
                try {
                    if (isCipherSupported(endpoint, tlsVersion, cipher)) {
                        supportedCiphers.add(cipher);
                    }
                } catch (Exception e) {
                    System.err.println("[" + endpoint + "] Error checking cipher " + cipher + " with " + tlsVersion
                            + ": " + e.getMessage());
                }
            }

            tlsCipherMap.put(tlsVersion, supportedCiphers);
        }

        return new EndpointResult(endpoint, tlsCipherMap);
    }

    private static String[] getCipherSuitesForTLSVersion(String tlsVersion) {
        try {
            SSLContext sslContext = SSLContext.getInstance(tlsVersion);
            sslContext.init(null, null, null);
            SSLSocketFactory factory = sslContext.getSocketFactory();
            return factory.getSupportedCipherSuites();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("TLS Version " + tlsVersion + " not supported: " + e.getMessage());
            return new String[0];
        } catch (KeyManagementException e) {
            System.err.println("Key management exception for " + tlsVersion + ": " + e.getMessage());
            return new String[0];
        }
    }

    private static boolean isCipherSupported(Endpoint endpoint, String tlsVersion, String cipher) {
        SSLContext sslContext;
        try {
            sslContext = SSLContext.getInstance(tlsVersion);
            sslContext.init(null, null, null);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            System.err.println(
                    "[" + endpoint + "] SSLContext initialization failed for " + tlsVersion + ": " + e.getMessage());
            return false;
        }

        SSLSocketFactory factory = sslContext.getSocketFactory();
        try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
            socket.setSoTimeout(CONNECTION_TIMEOUT);
            socket.setEnabledProtocols(new String[] { tlsVersion });
            socket.setEnabledCipherSuites(new String[] { cipher });
            SSLParameters sslParameters = socket.getSSLParameters();
            sslParameters.setServerNames(Collections.singletonList(new SNIHostName(endpoint.getHost())));
            socket.setSSLParameters(sslParameters);
            socket.connect(new InetSocketAddress(endpoint.getHost(), endpoint.getPort()), CONNECTION_TIMEOUT);
            socket.startHandshake();
            return true;
        } catch (SSLHandshakeException e) {
            return false;
        } catch (IOException e) {
            return false;
        }
    }

    private static void printEndpointResult(EndpointResult result) {
        System.out.println("Endpoint: " + result.getEndpoint());
        if (result.getTlsCipherMap().isEmpty()) {
            System.out.println("  No supported cipher suites found.\n");
            return;
        }

        for (String tlsVersion : TLS_VERSIONS) {
            List<String> ciphers = result.getTlsCipherMap().get(tlsVersion);
            String tlsVersionFormatted = formatTLSVersion(tlsVersion);
            System.out.println("  " + tlsVersionFormatted + " Supported Ciphers:");

            if (ciphers == null || ciphers.isEmpty()) {
                System.out.println("    - None\n");
            } else {
                for (String cipher : ciphers) {
                    System.out.println("    - " + cipher);
                }
                System.out.println();
            }
        }
    }

    private static String formatTLSVersion(String tlsVersion) {
        if (tlsVersion.startsWith("TLSv")) {
            return "TLS " + tlsVersion.substring(4);
        }
        return tlsVersion;
    }

    private static class Endpoint {
        private final String host;
        private final int port;

        public Endpoint(String host, int port) {
            this.host = host;
            this.port = port;
        }

        public String getHost() {
            return host;
        }

        public int getPort() {
            return port;
        }

        @Override
        public String toString() {
            return host + ":" + port;
        }
    }

    private static class EndpointResult {
        private final Endpoint endpoint;
        private final Map<String, List<String>> tlsCipherMap;

        public EndpointResult(Endpoint endpoint, Map<String, List<String>> tlsCipherMap) {
            this.endpoint = endpoint;
            this.tlsCipherMap = tlsCipherMap;
        }

        public Endpoint getEndpoint() {
            return endpoint;
        }

        public Map<String, List<String>> getTlsCipherMap() {
            return tlsCipherMap;
        }
    }
}
