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

import org.jasig.cas.authentication.principal.Credentials;

/**
 * Reperesent some self resolving Credentials.
 * This credentials know how to resolve the principalId themselves.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public interface IResolvingCredentials extends Credentials {

	/**
	 * Retrieve the principal Id.
	 * 
	 * @return the principal Id
	 */
	String getResolvedPrincipalId();
	
	/**
	 * Set the principal Id.
	 * 
	 * @param principalId the principal Id
	 */
	void setResolvedPrincipalId(String principalId);

}
