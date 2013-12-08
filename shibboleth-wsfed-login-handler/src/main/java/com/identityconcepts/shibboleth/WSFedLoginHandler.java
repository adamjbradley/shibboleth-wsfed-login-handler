/*
 * Copyright [2013] [Identity Concepts]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.identityconcepts.shibboleth;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mozilla.javascript.xml.XMLLib;
import org.opensaml.util.URLBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.AuthnResponseEndpointSelector;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextDeclRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Statement;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.SubjectLocality;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml1.*;
import org.opensaml.saml1.binding.*;
import org.opensaml.saml1.binding.artifact.*;
import org.opensaml.saml1.binding.decoding.*;
import org.opensaml.saml1.binding.encoding.*;
import org.opensaml.saml1.core.*;
import org.opensaml.saml1.core.impl.*;
import org.opensaml.saml1.core.validator.*;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.util.DatatypeHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.apache.commons.codec.binary.Base64;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;

import edu.internet2.middleware.shibboleth.idp.authn.provider.AbstractLoginHandler;

//XML Handlers
import org.opensaml.xml.parse.ParserPool;


import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.Request;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;


public class WSFedLoginHandler extends AbstractLoginHandler {
    private final Logger log = LoggerFactory.getLogger(WSFedLoginHandler.class);
    private static final String COOKIE_NAME = "shibboleth-processed";
      
	private static final String WA = "wsignin1.0";
	private static final String WS_FED_PROTOCOL_ENUM = "http://schemas.xmlsoap.org/ws/2003/07/secext";
	private static final Collection SUPPORTED_IDENTIFIER_FORMATS = Arrays.asList(new String[]{
			"urn:oasis:names:tc:SAML:1.1nameid-format:emailAddress", "http://schemas.xmlsoap.org/claims/UPN",
			"http://schemas.xmlsoap.org/claims/CommonName"});
	private static final String CLAIMS_URI = "http://schemas.xmlsoap.org/claims";

    
    private static String loginPageURL;
    private static String authenticationServletURL;
    private static String cookieDomain;

    public WSFedLoginHandler(String loginPageURL,
            String authenticationServletURL,
            String cookieDomain) {
        super();

        setSupportsPassive(false);
        setSupportsForceAuthentication(false);

        WSFedLoginHandler.loginPageURL = loginPageURL;
        WSFedLoginHandler.authenticationServletURL = authenticationServletURL;
        WSFedLoginHandler.cookieDomain = cookieDomain;
    }

    /**
     * Perform login with WSFedLoginHandler
     *
     * @param  request  HTTPServletRequest
     * @param  response HTTPServletResponse
     */
    public void login(final HttpServletRequest request,
            final HttpServletResponse response) {
        try {
            String redirectURL = null;
            if (isPassThrough(request.getCookies())) {
                log.debug("Cookie '{}' is set: continue with clientauthn protected servlet.", COOKIE_NAME);

                // construct URL for authenticationServlet
                redirectURL = getRedirectURL(request, authenticationServletURL);
            } else {
                // not passThrough
                log.debug("Cookie '{}' is not set: continue with x509 login page.", COOKIE_NAME);
                redirectURL = getRedirectURL(request, loginPageURL);
            }
            // send redirect
            if (! (redirectURL == null)) {
                log.debug("Redirect to {}", redirectURL);
                response.sendRedirect(redirectURL);
            } else {
                log.error("Could not set redirect URL, please check the configuration.");
            }
        } catch (IOException ex) {
            log.error("Unable to redirect to login page or authentication servlet.", ex);
        }

    }

    /**
     * return URL to which redirect will be done
     * depending on the X509 handler configuration,
     * a full URL will be used or a path in the web app
     *
     * @param  request  HTTPServletRequest
     * @return          URL for redirection
     */
    private String getRedirectURL(HttpServletRequest request,
            String url) {
        URLBuilder urlBuilder = null;
        // if URL configured
        if (url.startsWith("http")) {
            urlBuilder = new URLBuilder(url);
        } else {
            // if path configured
            log.debug("No URL configured in loginPageURL: {}", url);

            StringBuilder pathBuilder = new StringBuilder();
            urlBuilder = new URLBuilder();
            urlBuilder.setScheme(request.getScheme());
            urlBuilder.setHost(request.getServerName());
            // set port if not standard port
            if (! (request.getScheme().equals("http")) || (request.getScheme().equals("https"))) {
                urlBuilder.setPort(request.getServerPort());
            }

            pathBuilder.append(request.getContextPath());
            if (!loginPageURL.startsWith("/")) {
                pathBuilder.append("/");
            }
            pathBuilder.append(url);

            urlBuilder.setPath(pathBuilder.toString());
        }
        return urlBuilder.buildURL();
    }

    /**
     * check if pass-through cookie is set
     *
     * @param  cookies  set of cookies from request
     * @return          true or false
     */
    private boolean isPassThrough(Cookie[] cookies) {
        if (cookies == null) {
            return false;
        }
        log.trace("{} Cookie(s) are sent", cookies.length);
        for (int i=0; i<cookies.length; i++) {
            log.trace("Cookie name is {}", cookies[i].getName());
            if (cookies[i].getName().equals(COOKIE_NAME)) {
                return true;
            }
        }
        return false;
    }

    /**
     * set cookie for pass-through
     * cookieDomain can be configured in the handler config
     *
     * @param  path   path to which the client should return the cookie
     */
    public static Cookie createCookie(String path) {
        Cookie cookie = new Cookie(COOKIE_NAME, "1");
        cookie.setMaxAge(60*60*24*365);
        cookie.setPath(path);
        cookie.setSecure(true);
        // use cookieDomain if set
        if (!((cookieDomain == null) || (cookieDomain == ""))) {
            cookie.setDomain(cookieDomain);
        }
        return cookie;
    }           
}

