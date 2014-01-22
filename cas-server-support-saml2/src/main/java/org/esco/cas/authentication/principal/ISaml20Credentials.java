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
package org.esco.cas.authentication.principal;

import java.util.List;

import org.esco.cas.impl.SamlAuthInfo;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface ISaml20Credentials extends IInformingCredentials, IResolvingCredentials {

	/**
	 * Retrieve the authentication informations.
	 * 
	 * @return the authentication informations
	 */
	SamlAuthInfo getAuthenticationInformations();

	/**
	 * Attribute friendly name.
	 * 
	 * @param attributeFriendlyName the Attribute friendly name to set
	 */
	void setAttributeFriendlyName(String attributeFriendlyName);
	
	/**
	 * Attribute friendly name.
	 * 
	 * @return the Attribute friendly name
	 */
	String getAttributeFriendlyName();
	
	/**
	 * Attribute values.
	 * 
	 * @param attributesList the attribute values to set
	 */
	void setAttributeValues(List<String> attributesList);
	
	/**
	 * Attribute values.
	 * 
	 * @return the attribute values
	 */
	List<String> getAttributeValues();

}
