/*
 * Copyright [2012] [SWITCH]
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

package com.identityconcepts.shibboleth.shibboleth_wsfed_login_handler;

import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

import com.identityconcepts.shibboleth.shibboleth_wsfed_login_handler.*;

public class WSFedNamespaceHandler extends BaseSpringNamespaceHandler {

    /** Namespace URI. */
    public static final String NAMESPACE = "http://www.switch.ch/aai/idp/x509";

    public void init(){
        registerBeanDefinitionParser(WSFedLoginHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new WSFedLoginHandlerBeanDefinitionParser());
    }
}
