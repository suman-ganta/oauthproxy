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
  //public String issuer = "http://127.0.0.1:5556/dex";
  public String issuer = "https://idcs-4887c2ab59484d4b92e4cb4bd111891b.identity.oraclecloud.com/";

  @Option(names = {"-ci", "--clientId"}, description = "Client Id of OAuth client")
  //public String clientId = "oic-proxy-app";
  public String clientId = "5b17a6c1328a4ac1b95841c0d8497bc3";

  @Option(names = {"-cs", "--clientSecret"}, description = "Client Secret of OAuth client")
  //public String clientSecret = "mysecretoicclient";
  public String clientSecret = "0ed1e8a3-fc29-40da-9b71-da026ff8cf2d";

  @Option(names = {"-cb", "--callback"}, description = "Callback URI")
  public String redirectUri = "https://www.sumanganta.com/p/p/callback";
}
