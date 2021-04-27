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
package org.esco.sso.security.saml.om;

/**
 * Interface representing incoming data from outside (an IdP).
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface IIncomingSaml extends ISamlData {

	/**
	 * Unencoded (clear) request message.
	 * 
	 * @param samlMessage
	 */
	//void setSamlMessage(String samlMessage);

	/**
	 * Relay state.
	 * 
	 * @param relayState
	 */
	//void setRelayState(String relayState);

	/**
	 * Endpoint URL for request.
	 * 
	 * @param endpointUrl
	 */
	//void setEndpointUrl(String endpointUrl);
}