/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
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

package com.identityconcepts.shibboleth.authn;

import java.io.IOException;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.LoginContext;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;


/** Shibboleth Infocard login handler. */
public class InfocardSTSLoginHandler {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(InfocardSTSLoginHandler.class);

    /** Serial version UID. */
    private static final long serialVersionUID = -1234564934529536613L;

    /** Name of JAAS configuration used to authenticate users. */
    private String jaasConfigName = "InfocardUserPassAuth";

    /** init-param which can be passed to the servlet to override the default JAAS config. */
    private final String jaasInitParam = "jaasConfigName";

    private LoginContext infocardLoginContext;
    private MyCallbackHandler myCallbackHandler;

    // callback to give user and pw to auth system

    private class MyCallbackHandler implements CallbackHandler {
       private String username;
       private String password;
       public MyCallbackHandler(String user, String pass) {
          username = user;
          password = pass;
       }
       public MyCallbackHandler() {
          username = null;
          password = null;
       }
       public void setUsername(String user) {
          username = user;
       }
       public void setPassword(String pass) {
          password = pass;
       }
       public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
          for (int i = 0; i < callbacks.length; i++) {
             if (callbacks[i] instanceof TextOutputCallback) {
                 TextOutputCallback toc = (TextOutputCallback)callbacks[i];
                 log.error("Auth CB msg: " + toc.getMessage());
             } else if (callbacks[i] instanceof NameCallback) {
                 NameCallback nc = (NameCallback)callbacks[i];
                 nc.setName(username);
             } else if (callbacks[i] instanceof PasswordCallback) {
                 PasswordCallback pc = (PasswordCallback)callbacks[i];
                 pc.setPassword(password.toCharArray());
             } else {
                 log.error("Auth CB: Unrecognized Callback");
             }
         }

       }

     }

    /** Constructor. */
    public InfocardSTSLoginHandler() {
       try {
          myCallbackHandler = new MyCallbackHandler();
          infocardLoginContext = new LoginContext(jaasConfigName, myCallbackHandler);
       } catch (LoginException le) {
            log.error("Cannot create LoginContext. " + le.getMessage());
       } catch (SecurityException se) {
            log.error("Cannot create LoginContext. " + se.getMessage());
       }
    }

    public boolean authenticate(String user, String pw) {

       myCallbackHandler.setUsername(user);
       myCallbackHandler.setPassword(pw);

       try {

          infocardLoginContext.login();

       } catch (AccountExpiredException aee) {
          log.error("Account expired." );
          return (false);

       } catch (CredentialExpiredException cee) {
          log.error("Credentials expired.");
          return (false);

       } catch (FailedLoginException fle) {
          log.error("FailedLogin.");
          return (false);

       } catch (LoginException fle) {
          log.error("Login failed.");
          return (false);

       } catch (Exception e) {
           log.error("Unexpected Login Exception.");
          return (false);
       }
       
       return (true);

   }


}
