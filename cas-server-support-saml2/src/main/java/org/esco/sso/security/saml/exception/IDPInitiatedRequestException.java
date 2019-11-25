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
package org.esco.sso.security.saml.exception;

import org.apache.commons.lang.StringUtils;

import java.util.Arrays;
import java.util.Map;

/**
 * Indicate an IDPIntiatedRequest that we don't want to manage and to force a redirect to.
 * 
 * @author GIP RECIA 2019 - Julien Gribonvald.
 *
 */
public class IDPInitiatedRequestException extends Exception {

	Map<String, String[]> requestParams;

	public IDPInitiatedRequestException(final Map<String, String[]> params) {
		super();
		this.requestParams = params;
	}

	public IDPInitiatedRequestException(final Map<String, String[]> params, final String message, final Throwable cause) {
		super(message, cause);
		this.requestParams = params;
	}

	public IDPInitiatedRequestException(final Map<String, String[]> params, final String message) {
		super(message);
		this.requestParams = params;
	}

	public IDPInitiatedRequestException(final Map<String, String[]> params, final Throwable cause) {
		super(cause);
		this.requestParams = params;
	}

	public Map<String, String[]> getRequestParams() {
		return requestParams;
	}

	@Override
	public String toString() {
		return "IDPInitiatedRequestException{" +
				"requestParams=" + convertWithIteration(requestParams) +
				'}';
	}

	public String convertWithIteration(Map<String, String[]> map) {
		StringBuilder mapAsString = new StringBuilder("{");
		for (String key : map.keySet()) {
			mapAsString.append(key + "=" + Arrays.toString(map.get(key)) + ", ");
		}
		mapAsString.delete(mapAsString.length()-2, mapAsString.length()).append("}");
		return mapAsString.toString();
	}
}
