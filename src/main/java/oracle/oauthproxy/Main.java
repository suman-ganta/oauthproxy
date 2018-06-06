package oracle.oauthproxy;

import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.jersey.grizzly2.httpserver.GrizzlyHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;
import picocli.CommandLine;

import java.net.URI;

/**
 * Bootstraps the proxy
 */
public class Main {

    public static Options opts;

    /**
     * Starts Grizzly HTTP server exposing JAX-RS resources defined in this application.
     * @return Grizzly HTTP server.
     */
    public static HttpServer startServer(String baseUri) {
        final ResourceConfig rc = new ResourceConfig().packages("oracle.oauthproxy");
        return GrizzlyHttpServerFactory.createHttpServer(URI.create(baseUri), rc);
    }

    /**
     * Main method.
     * @param args
     */
    public static void main(String[] args) {
        Main.opts = CommandLine.populateCommand(new Options(), args);
        if (opts.usageHelpRequested) {
            CommandLine.usage(new Options(), System.out);
            return;
        }
        String baseUri = String.format("http://0.0.0.0:%s/", opts.port);
        final HttpServer server = startServer(baseUri);
        System.out.println(String.format("Proxy server started at " + baseUri));
        Runtime.getRuntime().addShutdownHook(new Thread(server::shutdownNow));
    }
}

