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

import org.esco.cas.authentication.handler.EmailAddressesAuthenticationStatusEnum;

/**
 * CAS Implementation for Email addresses credentials.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class EmailAddressesCredentials extends Saml20Credentials {

	/** SVUID. */
	private static final long serialVersionUID = 6280117516843013760L;

	/** Email addresses. */
	private List<String> emailAddresses;

	/** The one email address which is authenticated. */
	private String authenticatedEmailAddress;

	/** The authentication status. */
	private EmailAddressesAuthenticationStatusEnum authenticationStatus;

	@Override
	public String toString() {
		return "[email:" + this.authenticatedEmailAddress + "]";
	}

	/**
	 * Default constructor.
	 * 
	 * @param email ordered list of email adresses
	 */
	public EmailAddressesCredentials(final List<String> email) {
		this.emailAddresses = email;
	}

	/**
	 * Email addresses.
	 * 
	 * @return Email addresses
	 */
	public List<String> getEmailAddresses() {
		return this.emailAddresses;
	}

	/**
	 * Email addresses.
	 * 
	 * @param addresses Email addresses
	 */
	public void setEmailAddresses(final List<String> addresses) {
		this.emailAddresses = addresses;
	}

	/**
	 * The one email address which is authenticated.
	 * 
	 * @return authenticated email address
	 */
	public String getAuthenticatedEmailAddress() {
		return this.authenticatedEmailAddress;
	}

	/**
	 * The one email address which is authenticated.
	 * 
	 * @param emailAddressAuthenticated the authenticated email address
	 */
	public void setAuthenticatedEmailAddress(final String authenticatedEmailAddress) {
		this.authenticatedEmailAddress = authenticatedEmailAddress;
	}

	/**
	 * The authentication status.
	 * 
	 * @return the authentication status
	 */
	public EmailAddressesAuthenticationStatusEnum getAuthenticationStatus() {
		return this.authenticationStatus;
	}

	/**
	 * The authentication status.
	 * 
	 * @param authenticationStatus the authentication status
	 */
	public void setAuthenticationStatus(final EmailAddressesAuthenticationStatusEnum authenticationStatus) {
		this.authenticationStatus = authenticationStatus;
	}

}
