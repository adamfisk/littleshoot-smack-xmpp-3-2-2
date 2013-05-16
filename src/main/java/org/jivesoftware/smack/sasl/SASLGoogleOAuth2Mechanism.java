package org.jivesoftware.smack.sasl;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.net.Proxy;

import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.commons.lang3.StringUtils;
import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.SASLAuthentication;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.packet.Packet;
import org.jivesoftware.smack.proxy.ProxyInfo;
import org.jivesoftware.smack.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.oauth2.RefreshTokenRequest;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.auth.oauth2.TokenResponseException;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport.Builder;
import com.google.api.client.json.jackson.JacksonFactory;


public class SASLGoogleOAuth2Mechanism extends SASLMechanism {

    private final Logger log = LoggerFactory.getLogger(getClass());
    
    private String clientID;
    private String clientSecret;

    private String accessToken;
    private String refreshToken;

    private ConnectionConfiguration config;

    public SASLGoogleOAuth2Mechanism(SASLAuthentication sa) {
        super(sa);
    }

    @Override
    protected String getName() {
        return "X-OAUTH2";
    }

    @Override
    public void authenticate(String username, String pass, String host) 
        throws IOException, XMPPException {
        throw new XMPPException("Google doesn't support password authentication in OAuth2.");
    }

    @Override
    public void authenticate(String username, String host, CallbackHandler cbh) 
        throws IOException, XMPPException {

        //Set the authenticationID as the username, since they must be the same
        //in this case.
        this.authenticationId = username;
        this.hostname = host;

        // DRY warning: these must match the indices below.
        final TextInputCallback[] cbs = {new TextInputCallback("clientID"),
                                   new TextInputCallback("clientSecret"),
                                   new TextInputCallback("accessToken"),
                                   new TextInputCallback("refreshToken")};
        try {
            cbh.handle(cbs);
        } catch (final UnsupportedCallbackException e) {
            throw new IOException("UnsupportedCallback", e);
        }
        // DRY warning: these must match the order in the array above.
        clientID = cbs[0].getText();
        clientSecret = cbs[1].getText();
        accessToken = cbs[2].getText();
        refreshToken = cbs[3].getText();

        authenticate();
    }

    @Override
    public void authenticate(String username, String host,
            ConnectionConfiguration config) throws IOException, XMPPException {
        this.config = config;
        authenticate(username, host, config.getCallbackHandler());
    }
    
    @Override
    protected void authenticate() throws IOException, XMPPException {

        refreshAccessToken();

        final String raw = "\0" + this.authenticationId + "\0" + this.accessToken;
        final String authenticationText = Base64.encodeBytes(
                raw.getBytes("UTF-8"),
                Base64.DONT_BREAK_LINES);
        // Send the authentication to the server
        getSASLAuthentication().send(new Packet() {
            @Override
            public String toXML() {
                return "<auth mechanism=\"X-OAUTH2\""
                        + " auth:service=\"oauth2\""
                        + " xmlns:auth=\"http://www.google.com/talk/protocol/auth\""
                        + " xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">"
                        + authenticationText
                        + "</auth>";
            }
        });
    }

    private void refreshAccessToken() throws IOException {
        log.debug("Refreshing token with refresh: "+refreshToken+
            "\nclientId: "+clientID+
            "\nclientSecret:"+clientSecret);
        
        log.debug("Refreshing token called from:\n{}", dumpStack());
        
        try {
            refreshAccessToken(new NetHttpTransport());
        } catch (final IOException e) {
            // Try with a fallback proxy if we've got one.
            final HttpTransport ht = newTransportWithFallback();
            refreshAccessToken(ht);
        } finally {
            System.setProperty("https.proxyHost", "");
            System.setProperty("https.proxyPort", "");
        }
    }
    
    private HttpTransport newTransportWithFallback() {
        if (this.config != null) {
            final ProxyInfo info = this.config.getFallbackProxy();
            if (info != null) {
                final String pa = info.getProxyAddress();
                final int pp = info.getProxyPort();
                log.debug("Proxy: {}", pa);
                log.debug("Port: {}", pp);
                final Proxy proxy = 
                    new Proxy(Proxy.Type.HTTP, new InetSocketAddress(pa, pp));
                
                System.setProperty("https.proxyHost", pa);
                System.setProperty("https.proxyPort", String.valueOf(pp));
                
                final SSLSocketFactory ssl = this.config.getSslSocketFactory();
                final Builder http = new NetHttpTransport.Builder().setProxy(proxy);
                if (ssl != null) {
                    log.debug("Using ssl socket factory");
                    return http.setSslSocketFactory(ssl).build();
                } else {
                    log.debug("No ssl socket factory configured");
                    return http.build();
                }
            } else {
                log.debug("No fallback proxy configured");
                return new NetHttpTransport();
            }
        } else {
            log.debug("No config!");
            return new NetHttpTransport();
        }
    }

    private void refreshAccessToken(final HttpTransport httpTransport) 
            throws IOException {
        log.debug("Refreshing token with refresh: "+refreshToken+
            "\nclientId: "+clientID+
            "\nclientSecret:"+clientSecret);

        try {
            final TokenResponse response =
                new RefreshTokenRequest(httpTransport, 
                    new JacksonFactory(), new GenericUrl(
                        "https://accounts.google.com/o/oauth2/token"), refreshToken)
                    .setClientAuthentication(new ClientParametersAuthentication(
                        clientID, clientSecret))
                    .execute();
            final String token = response.getAccessToken();
            if (StringUtils.isNotBlank(token)) {
                log.debug("Got new access token!!");
                accessToken = token;
            } else {
                log.error("Retreived null access token in: {}", response);
                throw new IOException("Retreived null token?\n"+response);
            }
        } catch (final TokenResponseException e) {
            log.error("Token error -- maybe revoked or unauthorized?", e);
            throw new IOException("Problem with token -- maybe revoked?", e);
        } catch (final IOException e) {
            log.warn("IO exception while trying to refresh token.", e);
            throw e;
        }
    }
    
    /**
     * Returns the stack trace as a string.
     * 
     * @return The stack trace as a string.
     */
    public static String dumpStack() {
        return dumpStack(new Exception("Stack Dump Generated Exception"));
    }

    /**
     * Returns the stack trace as a string.
     * 
     * @param cause
     *            The thread to dump.
     * @return The stack trace as a string.
     */
    public static String dumpStack(final Throwable cause) {
        if (cause == null) {
            return "Throwable was null";
        }
        final StringWriter sw = new StringWriter();
        final PrintWriter s = new PrintWriter(sw);

        // This is very close to what Thread.dumpStack does.
        cause.printStackTrace(s);

        final String stack = sw.toString();
        try {
            sw.close();
        } catch (final IOException e) {
        }
        s.close();
        return stack;
    }
}
