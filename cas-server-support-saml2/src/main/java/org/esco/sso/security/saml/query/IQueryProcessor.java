/**
 * Copyright (C) 2012 RECIA http://www.recia.fr
 * @Author (C) 2012 Maxime Bossard <mxbossard@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * 
 */
package org.esco.sso.security.saml.query;

import org.esco.sso.security.saml.exception.SamlProcessingException;
import org.esco.sso.security.saml.exception.UnsupportedSamlOperation;
import org.esco.sso.security.saml.om.IIncomingSaml;

/**
 * IncomingQueryProcessor will fully process an incoming SAML request of a specific type.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public interface IQueryProcessor {

	/**
	 * Fully process the incoming SAML request.
	 * 
	 * @return the IIncomingSaml representation of the message
	 * @throws SamlProcessingException
	 * @throws UnsupportedSamlOperation
	 */
	IIncomingSaml processIncomingSamlMessage()
			throws SamlProcessingException, UnsupportedSamlOperation;

}
