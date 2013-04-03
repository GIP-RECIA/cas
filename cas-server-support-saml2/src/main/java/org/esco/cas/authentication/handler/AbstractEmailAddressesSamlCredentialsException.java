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
package org.esco.cas.authentication.handler;

import org.jasig.cas.authentication.handler.AuthenticationException;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public abstract class AbstractEmailAddressesSamlCredentialsException extends AuthenticationException {

	/** SVUID. */
	private static final long serialVersionUID = 502324913010237437L;

	/**
	 * Constructor that allows for the chaining of exceptions. Defaults to the
	 * default code provided for this exception.
	 * 
	 * @param throwable the chained exception.
	 */
	protected AbstractEmailAddressesSamlCredentialsException(final EmailAddressesAuthenticationStatusEnum status) {
		super(status.getStatusCode());
	}

	/**
	 * Retrieve the Authentication status code.
	 * 
	 * @return the Authentication status code
	 */
	public abstract EmailAddressesAuthenticationStatusEnum getStatusCode();

}
