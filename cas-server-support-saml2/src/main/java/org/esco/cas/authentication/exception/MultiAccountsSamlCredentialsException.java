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

package org.esco.cas.authentication.exception;

import org.esco.cas.authentication.handler.AuthenticationStatusEnum;
import org.jasig.cas.authentication.handler.UnsupportedCredentialsException;

/**
 * Exception thrown when SAML authentication match multiple accounts.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public final class MultiAccountsSamlCredentialsException extends AbstractSamlCredentialsException {

	/** Static instance of UnsupportedCredentialsException. */
	public static final UnsupportedCredentialsException ERROR = new UnsupportedCredentialsException();

	/** Unique ID for serializing. */
	private static final long serialVersionUID = 3977861752513837361L;

	/** The code description of this exception. */
	private static final AuthenticationStatusEnum STATUS = AuthenticationStatusEnum.MULTIPLE_ACCOUNTS;

	/**
	 * Default constructor that does not allow the chaining of exceptions and
	 * uses the default code as the error code for this exception.
	 */
	public MultiAccountsSamlCredentialsException() {
		super(MultiAccountsSamlCredentialsException.STATUS);
	}

	@Override
	public AuthenticationStatusEnum getStatusCode() {
		return MultiAccountsSamlCredentialsException.STATUS;
	}
}