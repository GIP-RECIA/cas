/**
 * 
 */
package org.esco.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.esco.cas.authentication.handler.EmailAddressesAuthenticationStatusEnum;
import org.esco.cas.authentication.principal.EmailAddressesCredentials;
import org.esco.cas.impl.SamlAuthInfo;
import org.esco.sso.security.saml.ISaml20IdpConnector;
import org.esco.sso.security.saml.om.IAuthentication;
import org.esco.sso.security.saml.om.impl.BasicSamlAuthentication;
import org.esco.sso.security.saml.query.impl.QueryAuthnRequest;
import org.esco.sso.security.saml.query.impl.QueryAuthnResponse;
import org.esco.sso.security.saml.query.impl.QuerySloRequest;
import org.esco.sso.security.saml.query.impl.QuerySloResponse;
import org.esco.sso.security.saml.util.SamlHelper;
import org.joda.time.DateTime;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations={"classpath:serializationTestContext.xml"})
public class SerializationTest {

	private static final String AUTH_SESSION_INDEX = "sid42";
	private static final String AUTH_SUBJECT_ID = "subject17";
	private static final String PARAM_KEY_1 = "key1";
	private static final String PARAM_KEY_2 = "key2";
	private static final String PARAM_VALUE_1_1 = "value11";
	private static final String PARAM_VALUE_1_2 = "value12";
	private static final String PARAM_VALUE_2_1 = "value21";
	private static final DateTime AUTH_INSTANT_1 = new DateTime(100000L);
	private static final DateTime AUTH_INSTANT_2 = new DateTime(200000L);
	private static final String CREDS_PRINCIPAL_ID = "userToto";

	@Test
	public void testQueryAuthnRequestSerialization() throws Exception {
		final String requestId = "Request42!";
		final String idpConfigId = "testIdpConfig1";
		
		final QueryAuthnRequest query = this.buildQueryAuthnRequest(requestId, idpConfigId);
		final ISaml20IdpConnector idpConnectorBuilder = query.getIdpConnectorBuilder();
		final Map<String, String[]> parametersMap = query.getParametersMap();
		
		final QueryAuthnRequest deserializedQuery = this.testSerialization(query);

		Assert.assertEquals("Bad id retrieved following serialization process !", requestId, deserializedQuery.getId());
		Assert.assertEquals("Bad IdP connector retrieved following serialization process !", idpConnectorBuilder, deserializedQuery.getIdpConnectorBuilder());
		
		this.assertParametersMapEquals(parametersMap, deserializedQuery.getParametersMap());
	}
	
	@Test
	public void testQueryAuthnResponseSerialization() throws Exception {
		final String responseId = "ResponseToRequest42!";
		final String originalRequestId = "Request42!";
		final String idpConfigId = "testIdpConfig1";

		final QueryAuthnResponse query = this.buildQueryAuthnResponse(responseId, originalRequestId, idpConfigId);
		
		QueryAuthnResponse deserializedQuery = this.testSerialization(query);
		
		Assert.assertEquals("Bad id retrieved following serialization process !", query.getId(), deserializedQuery.getId());
		Assert.assertEquals("Bad inResponseToId retrieved following serialization process !", query.getInResponseToId(), deserializedQuery.getInResponseToId());
		Assert.assertEquals("Bad riginal request Id retrieved following serialization process !", query.getOriginalRequest().getId(), deserializedQuery.getOriginalRequest().getId());
		Assert.assertNotNull("Saml auth list should not be null following serialization process !", deserializedQuery.getSamlAuthentications());
		Assert.assertEquals("Bad saml auth list cardinality retrieved following serialization process !", query.getSamlAuthentications().size(), deserializedQuery.getSamlAuthentications().size());
	}
	
	@Test
	public void testQuerySloRequesterialization() throws Exception {
		final String requestId = "RequestSlo42!";
		final String idpConfigId = "testIdpConfig2";

		final QuerySloRequest query = this.buildQuerySloRequest(requestId, idpConfigId);
		
		QuerySloRequest deserializedQuery = this.testSerialization(query);
		
		Assert.assertEquals("Bad id retrieved following serialization process !", query.getId(), deserializedQuery.getId());
		Assert.assertEquals("Bad IdpConnector builder retrieved following serialization process !", query.getIdpConnectorBuilder(), deserializedQuery.getIdpConnectorBuilder());
	}
	
	@Test
	public void testQuerySloResponseSerialization() throws Exception {
		final String responseId = "RequestSlo44!";
		final String originalRequestId = "Request46662!";
		final String idpConfigId = "testIdpConfig3";

		final QuerySloResponse query = this.buildQuerySloResponse(responseId, originalRequestId, idpConfigId);
		
		QuerySloResponse deserializedQuery = this.testSerialization(query);
		
		Assert.assertEquals("Bad id retrieved following serialization process !", query.getId(), deserializedQuery.getId());
		Assert.assertEquals("Bad inResponseToId retrieved following serialization process !", query.getInResponseToId(), deserializedQuery.getInResponseToId());
		Assert.assertEquals("Bad original request Id retrieved following serialization process !", query.getOriginalRequest().getId(), deserializedQuery.getOriginalRequest().getId());
	}
	
	@Test
	public void testSamlAuthInfoSerialization() throws Exception {
		final String idpEntityId = "http://www.recia.fr/idp2";

		final SamlAuthInfo info = this.buildSamlAuthInfo(idpEntityId);
		
		SamlAuthInfo deserializedInfo = this.testSerialization(info);
		
		Assert.assertEquals("Bad IdP entity Id retrieved following serialization process !", info.getIdpEntityId(), deserializedInfo.getIdpEntityId());
		Assert.assertEquals("Bad IdP subject retrieved following serialization process !", info.getIdpSubject(), deserializedInfo.getIdpSubject());
		Assert.assertEquals("Bad session index retrieved following serialization process !", info.getSessionIndex(), deserializedInfo.getSessionIndex());
	}
	
	@Test
	public void testEmailAddressesCredentialsSerialization() throws Exception {
		final String idpConfigId = "testIdpConfig2";
		final String email1 = "email@one.fr";
		final String email2 = "email@two.fr";

		final EmailAddressesCredentials creds = this.buildEmailAddressesCredentials(idpConfigId, email1, email2);
		
		EmailAddressesCredentials deserializedCreds = this.testSerialization(creds);
		
		Assert.assertEquals("Bad authenticated email address retrieved following serialization process !", creds.getAuthenticatedEmailAddress(), deserializedCreds.getAuthenticatedEmailAddress());
		Assert.assertEquals("Bad authentication status retrieved following serialization process !", creds.getAuthenticationStatus(), deserializedCreds.getAuthenticationStatus());
		Assert.assertEquals("Bad email adresses retrieved following serialization process !", creds.getEmailAddresses().toString(), deserializedCreds.getEmailAddresses().toString());
		Assert.assertEquals("Bad principal Id retrieved following serialization process !", creds.getPrincipalId(), deserializedCreds.getPrincipalId());
		Assert.assertNotNull("Authentication informations should not be null following serialization process !", deserializedCreds.getAuthenticationInformations());
		Assert.assertEquals("Bad auth infos retrieved following serialization process !", creds.getAuthenticationInformations().getIdpEntityId(), deserializedCreds.getAuthenticationInformations().getIdpEntityId());

	}
	
	/**
	 * Build a QueryAuthnRequest with parameterized requestId and idpConfigId.
	 * Contains fix parameter map described with PARAM_KEY_1, PARAM_VALUE_1_1, PARAM_VALUE_1_2 ; PARAM_KEY_2 PARAM_VALUE_2_1.
	 * @param requestId
	 * @param idpConfigId
	 * @return
	 */
	protected QueryAuthnRequest buildQueryAuthnRequest(String requestId, String idpConfigId) {
		final ISaml20IdpConnector idpConnectorBuilder = SamlHelper.getWayfConfig().findIdpConfigById(idpConfigId).getSaml20IdpConnector();

		String key1 = PARAM_KEY_1;
		String key2 = PARAM_KEY_2;
		String[] value1 = new String[]{PARAM_VALUE_1_1, PARAM_VALUE_1_2};
		String[] value2 = new String[]{PARAM_VALUE_2_1};
		Map<String, String[]> parametersMap = new TreeMap<String, String[]>();
		parametersMap.put(key1, value1);
		parametersMap.put(key2, value2);
		parametersMap = Collections.unmodifiableMap(parametersMap);
		
		QueryAuthnRequest query = new QueryAuthnRequest(requestId, idpConnectorBuilder, parametersMap);
		
		return query;
	}
	
	/**
	 * Build a QueryAuthnResponse with parameterized responseId, originalRequestId and idpConfigId.
	 * Contains 2 BasicSamlAuthentication on AUTH_INSTANT_1 & AUTH_INSTANT_2.
	 * 
	 * @param responseId
	 * @param originalRequestId
	 * @param idpConfigId
	 * @return
	 */
	protected QueryAuthnResponse buildQueryAuthnResponse(String responseId, String originalRequestId, String idpConfigId) {
		QueryAuthnResponse query = new QueryAuthnResponse(responseId);
		
		query.setInResponseToId(originalRequestId);
		QueryAuthnRequest request = this.buildQueryAuthnRequest(originalRequestId, idpConfigId);
		query.setOriginalRequest(request);
		
		List<IAuthentication> authns = new ArrayList<IAuthentication>();
		authns.add(this.buildBasicSamlAuthentication(AUTH_INSTANT_1));
		authns.add(this.buildBasicSamlAuthentication(AUTH_INSTANT_2));
		query.setSamlAuthentications(authns);
		
		return query;
	}
	
	/**
	 * Build a BasicSamlAuthentication with parameterized authInstant and constant AUTH_SESSION_INDEX & AUTH_SUBJECT_ID.
	 * 
	 * @param authInstant
	 * @return
	 */
	protected BasicSamlAuthentication buildBasicSamlAuthentication(DateTime authInstant) {
		BasicSamlAuthentication auth = new BasicSamlAuthentication();
		auth.setAuthenticationInstant(authInstant);
		auth.setSessionIndex(AUTH_SESSION_INDEX);
		auth.setSubjectId(AUTH_SUBJECT_ID);
		
		return auth;
	}
	
	/**
	 * Build a QuerySloRequest with parameterized requestId and idpConfigId.
	 * 
	 * @param requestId
	 * @param idpConfigId
	 * @return
	 */
	protected QuerySloRequest buildQuerySloRequest(String requestId, String idpConfigId) {
		final ISaml20IdpConnector idpConnectorBuilder = SamlHelper.getWayfConfig().findIdpConfigById(idpConfigId).getSaml20IdpConnector();

		QuerySloRequest query = new QuerySloRequest(requestId, idpConnectorBuilder);

		return query;
	}
	
	/**
	 * Build a QuerySloResponse with parameterized responseId, originalRequestId and idpConfigId.
	 * 
	 * @param responseId
	 * @param originalRequestId
	 * @param idpConfigId
	 * @return
	 */
	protected QuerySloResponse buildQuerySloResponse(String responseId, String originalRequestId, String idpConfigId) {
		QuerySloResponse query = new QuerySloResponse(responseId);
		query.setInResponseToId(originalRequestId);
		query.setOriginalRequest(this.buildQuerySloRequest(originalRequestId, idpConfigId));

		return query;
	}
	
	protected SamlAuthInfo buildSamlAuthInfo(String idpEntityId) {
		SamlAuthInfo info = new SamlAuthInfo();
		info.setIdpEntityId(idpEntityId);
		info.setIdpSubject(AUTH_SUBJECT_ID);
		info.setSessionIndex(AUTH_SESSION_INDEX);
		
		return info;
	}
	
	protected EmailAddressesCredentials buildEmailAddressesCredentials(String idpEntityId, String... emails) {
		List<String> emailList = (List<String>) Arrays.asList(emails);
		EmailAddressesCredentials creds = new EmailAddressesCredentials(emailList);
		creds.setAuthenticatedEmailAddress(emails[0]);
		creds.setPrincipalId(CREDS_PRINCIPAL_ID);
		creds.setAuthenticationStatus(EmailAddressesAuthenticationStatusEnum.AUTHENTICATED);
		
		SamlAuthInfo infos = creds.getAuthenticationInformations();
		SamlAuthInfo newInfo = this.buildSamlAuthInfo(idpEntityId);
		
		infos.setIdpEntityId(newInfo.getIdpEntityId());
		infos.setIdpSubject(newInfo.getIdpSubject());
		infos.setSessionIndex(newInfo.getSessionIndex());
		
		return creds;
	}

	/**
	 * Compare 2 Maps. The maps need to have same keys same values and same iteration order to be represented as equals.
	 * 
	 * @param expected
	 * @param actual
	 */
	protected void assertParametersMapEquals(final Map<String, String[]> expected, final Map<String, String[]> actual) {
		Assert.assertNotNull("Expected parameters map should not be null !", expected);
		Assert.assertNotNull("Actual parameters map should not be null !", actual);
		
		Assert.assertEquals("Parameters map have wrong cardinality !", expected.entrySet().size(), actual.entrySet().size());
		
		List<String> expectedKeyList = new ArrayList<String>(expected.keySet());
		Collections.sort(expectedKeyList);
		List<String> actualKeyList = new ArrayList<String>(actual.keySet());
		Collections.sort(actualKeyList);
		
		Iterator<String> expIt = expectedKeyList.iterator();
		Iterator<String> actIt = actualKeyList.iterator();
		
		while (expIt.hasNext()) {
			String expectedKey = expIt.next();
			String actualKey = actIt.next();
			
			Assert.assertEquals("Parameters map key are differents !", expectedKey, actualKey);
			String[] expectedValue = expected.get(expectedKey);
			String[] actualValue = actual.get(actualKey);
			
			if (expectedValue != null) {
				Assert.assertNotNull("Parameters map value should not be null !", actualValue);
				Assert.assertEquals("Parameters map value have wrong cardinality !", expectedValue.length, actualValue.length);
				for (int k = 0; k < expectedValue.length; k++) {
					Assert.assertEquals("Parameters map value is different !", expectedValue[k], actualValue[k]);
				}
			} else {
				Assert.assertNull("Parameters map value should be null !", actualValue);
			}
		}		
	}
	
	@SuppressWarnings("unchecked")
	protected <T> T testSerialization(T object) throws IOException, ClassNotFoundException {
		Assert.assertNotNull("Supplied object to test serialization to should not be null !", object);
		
		Object deserializedObject = null;
		
		// Serialization of object
		ByteArrayOutputStream out = new ByteArrayOutputStream();
	    ObjectOutputStream oos = new ObjectOutputStream(out);
	    oos.writeObject(object);
	    oos.close();
	    
	    byte[] serializedObject = out.toByteArray();
	    out.close();
	    
	    // Deserialization of object
	    ByteArrayInputStream in = new ByteArrayInputStream(serializedObject);
	    ObjectInputStream ois = new ObjectInputStream(in);
	    deserializedObject = ois.readObject();
	    
	    Assert.assertNotNull("Deserialized object should not be null !", deserializedObject);
	    Assert.assertEquals("Deserialized object got wrong type !", object.getClass(), deserializedObject.getClass());
		
	    return (T) deserializedObject;
	}
	
}
