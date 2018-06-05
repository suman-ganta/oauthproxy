package oracle.oauthproxy;

import com.auth0.json.auth.TokenHolder;
import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static javax.ws.rs.core.Cookie.DEFAULT_VERSION;
import static javax.ws.rs.core.NewCookie.DEFAULT_MAX_AGE;

/**
 * Root resource (exposed at "p" path)
 */
@Path("p")
public class OpenIDProxyResource {
    private final String issuer = Main.opts.issuer;
    private final String spec = issuer + "/keys";
    private final String clientId = Main.opts.clientId;
    private final String clientSecret = Main.opts.clientSecret;
    private final String domain = issuer;
    private final String redirectUri = Main.opts.redirectUri;
    private final String state = "I wish to wash my irish wristwatch";
    private static final String scope = "openid profile email offline_access";
    private static final String AUTH_COOKIE_NAME = "idtoken";
    public static final String REDIRECT_COOKIE_NAME = "org";

    @Context UriInfo proxyUri;
    @Context javax.ws.rs.core.Request req;

    private ObjectMapper mapper = new ObjectMapper();
    private static final Logger LOG = LoggerFactory.getLogger(OpenIDProxyResource.class);

  /**
   * Initiates OpenID login flow. Basically does a redirect (via browser) to OpenID server requesting auth code.
   * @param sc
   * @param redirect
   * @return
   */
    @Path("login")
    @GET
    public javax.ws.rs.core.Response login(@QueryParam("scope") @DefaultValue(value = scope) String sc,
        @HeaderParam("X-Auth-Request-Redirect") String redirect){
        HttpUrl httpUrl = HttpUrl.parse(domain);
        httpUrl = httpUrl.newBuilder().addPathSegment("auth")
            .addQueryParameter("client_id", clientId)
            .addQueryParameter("redirect_uri", redirectUri)
            .addQueryParameter("response_type", "code")
            .addQueryParameter("scope", sc)
            .addQueryParameter("state", state).build();
        LOG.debug(httpUrl.toString());
      final NewCookie originalUrl = new NewCookie(REDIRECT_COOKIE_NAME, redirect,
          "/", null, DEFAULT_VERSION, null, DEFAULT_MAX_AGE, null, false,
          false);
        return javax.ws.rs.core.Response.status(javax.ws.rs.core.Response.Status.FOUND).location(httpUrl.uri()).
            cookie(originalUrl).build();
    }

  /**
   * This callback endpoint is registered with oauth client on OpenID server. OpenID server responds to the above request
   * with a redirect (via browser) to this endpoint along with auth code.
   * This one performs exchanging auth code with access token (using okhttp client).
   * After successful completion, the id token is stored as cookie for future requests
   * Also it perform redirect to original url which triggered login flow.
   * @param code
   * @param state
   * @param org
   * @return
   */
    @Path("callback")
    @GET
    public javax.ws.rs.core.Response callback(@QueryParam("code") String code, @QueryParam("state") String state,
        @CookieParam(REDIRECT_COOKIE_NAME) @DefaultValue("/bpm/api/4.0/dp-executions") String org){
        //exchange
        HttpUrl httpUrl = HttpUrl.parse(domain);
        httpUrl = httpUrl.newBuilder().addPathSegment("token").build();
        OkHttpClient client = new OkHttpClient();
        LOG.debug(httpUrl.toString());
        RequestBody formBody = new FormBody.Builder()
            .add("client_id", clientId)
            .add("client_secret", clientSecret)
            .add("grant_type", "authorization_code")
            .add("code", code)
            .add("redirect_uri", redirectUri)
            .build();
        Request request = new Request.Builder().url(httpUrl).post(formBody).build();
        try {
            Response response = client.newCall(request).execute();
            LOG.debug(response.toString());
            final ResponseBody body = response.body();
            String payload = body.string();
            LOG.debug(payload);
            TokenHolder tokenHolder = mapper.readValue(payload, TokenHolder.class);

            //now token is here, lets set it as cookie
            final URI location = URI.create(org);
            final NewCookie authCookie = new NewCookie(AUTH_COOKIE_NAME, tokenHolder.getIdToken(),
              "/", location.getAuthority(), DEFAULT_VERSION, null, DEFAULT_MAX_AGE, null, false,
              false);

            //redirect to original request
            return javax.ws.rs.core.Response.status(javax.ws.rs.core.Response.Status.FOUND).location(location).
              cookie(authCookie).build();
        } catch (IOException e) {
            LOG.error(e.getMessage(), e);
        }
        return null;
    }

    /**
     * This is used by nginx auth_request directive to check if a given request is authenticated.
     * accepts jwt token as cookie or as Authorization header
     */
    @Path("/auth")
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public javax.ws.rs.core.Response validateToken(@HeaderParam("Authorization") String authzHeader,
        @CookieParam(value = AUTH_COOKIE_NAME) String authCookie) {
        String token = null;
        if (authzHeader != null) {
            final String[] strings = authzHeader.split("//s+");
            token = strings[1];
        }else if(authCookie != null){
            token = authCookie;
        }
        if(token == null || token.isEmpty())
            return javax.ws.rs.core.Response.status(javax.ws.rs.core.Response.Status.UNAUTHORIZED).build();
        Jwk jwk;
        try {
            JwkProvider provider = new UrlJwkProvider(new URL(spec));

            DecodedJWT jwt = JWT.decode(token);
            final Claim kid = jwt.getHeaderClaim("kid");
            jwk = provider.get(kid.asString());
            final PublicKey publicKey = jwk.getPublicKey();

            RSAPrivateKey privateKey = null;//Get the key instance
            try {
                Algorithm algorithm = Algorithm.RSA256((RSAPublicKey)publicKey, privateKey);

                JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(issuer)
                    .build(); //Reusable verifier instance
                verifier.verify(token);
            } catch (JWTVerificationException e){
                LOG.error(e.getMessage(), e);
            }

            return javax.ws.rs.core.Response.ok().build();
        } catch (JwkException e) {
            LOG.error(e.getMessage(), e);
        } catch (MalformedURLException e) {
            LOG.error(e.getMessage(), e);
        }
        return null;
    }
}
