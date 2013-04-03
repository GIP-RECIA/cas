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

/**
 * Status of the SAML email adresse authentication.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public enum EmailAddressesAuthenticationStatusEnum {

	/** The SAML response returned nothing. */
	EMPTY_EMAIL_CREDENTIAL("error.authentication.saml.email.credentials.empty"),

	/** The SAML response returned more than one email. */
	NOT_UNIQUE_EMAIL_CREDENTIAL("error.authentication.saml.email.credentials.notUnique"),

	/** The SAML response returned an email bind to no account. */
	NO_ACCOUNT("error.authentication.saml.email.noAccount"),

	/** The SAML response returned an email bind to multiple accounts. */
	MULTIPLE_ACCOUNTS("error.authentication.saml.email.multipleAccounts"),

	/** Cannot authenticate the user for another reason. */
	NOT_AUTHENTICATED("error.authentication.saml.email.anotherReason"),

	/** The SAML response returned an email which could be authenticated. */
	AUTHENTICATED("success.authentication.saml.email");

	/** The status code. */
	private String statusCode;

	private EmailAddressesAuthenticationStatusEnum(final String statusCode) {
		this.statusCode = statusCode;
	}

	public String getStatusCode() {
		return this.statusCode;
	}

}
