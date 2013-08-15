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

import java.security.Principal;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.AuthnContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;


public class WSFedLoginServlet extends HttpServlet {

	private static final long serialVersionUID = -4431927396568561030L;
	private final Logger log = LoggerFactory.getLogger(WSFedLoginServlet.class);
    private static final String GETPAR_PASSTHROUGH = "x509-pass-through";
    public void init() {
        log.trace("servlet initialization");
    }

    protected void service(HttpServletRequest request, HttpServletResponse response) {
        log.trace("servlet service");

        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        log.debug("{} X509Certificates found in request", certs.length);

        if (certs.length < 1) {
            log.error("No X509Certificates found in request");
            request.setAttribute(LoginHandler.AUTHENTICATION_ERROR_KEY, "No X509Certificates found in request");
            AuthenticationEngine.returnToAuthenticationEngine(request, response);
        }

        // Take only the end entity certificate
        X509Certificate cert = certs[0];
        
        Subject subject = new Subject();
        Set<Principal> principals = subject.getPrincipals();
        
        // Add the cert to the public credentials of the subject
        Set<Object> publicCredentials = subject.getPublicCredentials();
        publicCredentials.add(cert);
        
        log.debug("Adding SubjectX500Principal {} of type {} as principal to subject", cert.getSubjectX500Principal(), X500Principal.class);
        principals.add(cert.getSubjectX500Principal());
               
        try {
            if (cert.getSubjectAlternativeNames() != null) {
            	log.debug("Certificate contains {} subjectAlternativeNames", cert.getSubjectAlternativeNames().size());
	        	for (List<?> subjectAltName : cert.getSubjectAlternativeNames()) {
	        		switch ((Integer) subjectAltName.get(0)) {	        			
	        			default:
	        				log.debug("No cases handled");
	        				break;
	        		}
				}
            } else {
            	log.debug("Certificate contains no subjectAlternativeNames");
            }
		} catch (CertificateParsingException e) {
			log.error("Exception while parsing certificate {}", cert, e);
		}

        log.debug("Forward subject {} to the AuthenticationEngine", subject); 
        request.setAttribute(LoginHandler.SUBJECT_KEY, subject);
        
        log.debug("GET parameter {} is {}", GETPAR_PASSTHROUGH, request.getParameter(GETPAR_PASSTHROUGH));
        if (request.getParameter(GETPAR_PASSTHROUGH) != null) {
            Cookie cookie = WSFedLoginHandler.createCookie(request.getContextPath());
            log.trace("Set Cookie {}", cookie);
            response.addCookie(cookie);
        }

        this.log.trace("Set request attribute {} to {}", LoginHandler.AUTHENTICATION_METHOD_KEY, AuthnContext.PASSWORD_AUTHN_CTX);
        request.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, AuthnContext.PASSWORD_AUTHN_CTX);
        AuthenticationEngine.returnToAuthenticationEngine(request, response);
    }

}
