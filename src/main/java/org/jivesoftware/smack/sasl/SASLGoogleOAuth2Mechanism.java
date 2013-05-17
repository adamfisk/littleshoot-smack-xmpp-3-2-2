package org.jivesoftware.smack.sasl;

import java.io.IOException;
import java.util.logging.Handler;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.HttpClient;
import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.SASLAuthentication;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.packet.Packet;
import org.jivesoftware.smack.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.oauth2.RefreshTokenRequest;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.auth.oauth2.TokenResponseException;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.apache.ApacheHttpTransport;
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
            ConnectionConfiguration conf) throws IOException, XMPPException {
        this.config = conf;
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
        log.debug("Refreshing ACCESS token");
        
//        Called from authenticate in this class via:
//            at org.jivesoftware.smack.SASLAuthentication.authenticate(SASLAuthentication.java:320)
//            at org.jivesoftware.smack.XMPPConnection.login(XMPPConnection.java:207)
//            at org.littleshoot.commom.xmpp.GoogleOAuth2Credentials.login(GoogleOAuth2Credentials.java:79)
//            at org.littleshoot.commom.xmpp.XmppUtils.newConnection(XmppUtils.java:602)
            
        //enableLogging();
        final HttpClient directClient = this.config.getDirectHttpClient();
        final HttpClient proxiedClient = this.config.getProxiedHttpClient();
        try {
            refreshAccessToken(new ApacheHttpTransport(directClient));
        } catch (final IOException e) {
            refreshAccessToken(new ApacheHttpTransport(proxiedClient));
        }
    }

    private void refreshAccessToken(final HttpTransport httpTransport) 
            throws IOException {
        log.debug("Refreshing ACCESS token...");

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

    private void enableLogging() {
        // Grab java logs in log4j.
        final java.util.logging.Logger logger = 
            java.util.logging.Logger.getLogger(HttpTransport.class.getName());
        logger.setLevel(java.util.logging.Level.CONFIG);
        logger.addHandler(new Handler() {

            @Override
            public void close() throws SecurityException {
            }

            @Override
            public void flush() {
            }

            @Override
            public void publish(java.util.logging.LogRecord record) {
                log.debug(record.getMessage());
            }
        });
    }
}
