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

package com.identityconcepts.shibboleth.profile;

import java.util.HashSet;
import java.util.Map;
import org.opensaml.common.SAMLObject;
import java.security.cert.Certificate;

/**
 * Infocard STS configuration settings.
 */
public class WSTrustRequest {

   public String principalName;
   public String relyingPartyID;
   public String realRelyingParty;
   public SAMLObject message;
   public SAMLObject assertion;
   public HashSet<String> requestedAttributes;
   public Map<String, String> displayAttributes;
   public Certificate realRelyingPartyCertificate;
}

