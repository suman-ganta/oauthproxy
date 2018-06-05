package oracle.oauthproxy;

import picocli.CommandLine;

import static picocli.CommandLine.Option;

/**
 * Options class to hold all command line options
 */
@CommandLine.Command(showDefaultValues = true)
public class Options {
  @Option(names = {"-h", "--help"}, usageHelp = true, description = "display this help message")
  boolean usageHelpRequested;

  @Option(names = {"-p", "--port"}, description = "Http port to run this proxy on")
  public Integer port = 8090;

  @Option(names = {"-i", "--issuer"}, description = "Token issuer url, OpenID issuer url")
  public String issuer = "http://127.0.0.1:5556/dex";

  @Option(names = {"-ci", "--clientId"}, description = "Client Id of OAuth client")
  public String clientId = "oic-proxy-app";

  @Option(names = {"-cs", "--clientSecret"}, description = "Client Secret of OAuth client")
  public String clientSecret = "mysecretoicclient";

  @Option(names = {"-cb", "--callback"}, description = "Callback URI")
  public String redirectUri = "http://127.0.0.1:8089/p/callback";
}
