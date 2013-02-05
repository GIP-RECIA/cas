/**
 * 
 */
package org.esco.sso.security.saml.opensaml;

import java.io.IOException;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.esco.sso.security.saml.ISaml20IdpConnector;
import org.esco.sso.security.saml.SamlBindingEnum;
import org.esco.sso.security.saml.SamlResponseData;
import org.joda.time.DateTime;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockServletContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Tests d'intégration de la library opensaml2 dans le SP Processor.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
@RunWith(value=SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations="classpath:openSaml20SpProcessorContext.xml")
public class OpenSaml20ProcessingTest {

	private static final String RESOURCE_BASE_PATH = "test";

	private static final String SAML_ATTRIBUTE_KEY = "ctemail";

	private static final Object SAML_ATTRIBUTE_VALUE = "testValue";

	@javax.annotation.Resource(name="responseSimpleSigned")
	private ClassPathResource responseSimpleSigned;

	@javax.annotation.Resource(name="responseAttacked1")
	private ClassPathResource responseAttacked1;

	@javax.annotation.Resource(name="responseAttacked2")
	private ClassPathResource responseAttacked2;

	@javax.annotation.Resource(name="responseFullSigned")
	private ClassPathResource responseFullSigned;

	@Autowired
	private OpenSaml20SpProcessor spProcessor;

	@Autowired
	private ISaml20IdpConnector idpConnector;

	@BeforeClass
	public static void initOpenSaml() throws ConfigurationException {
		DefaultBootstrap.bootstrap();
	}

	/**
	 * Basic test a standard simple signed response.
	 * => using testProcessSaml20AuthnResponseProcessing1()
	 * 
	 * @throws Exception
	 */
	@Test
	public void testSimpleSignedResponseProcessing1() throws Exception {
		SamlResponseData samlResponseData =
				this.testProcessSaml20AuthnResponseProcessing1(this.responseSimpleSigned, SamlBindingEnum.SAML_20_HTTP_POST);

		List<String> samlAttributes = samlResponseData.getAttribute(OpenSaml20ProcessingTest.SAML_ATTRIBUTE_KEY);
		Assert.assertEquals("SAML attributes list size is incorrect !", 1, samlAttributes.size());
		Assert.assertEquals("SAML attribute value is incorrect !", OpenSaml20ProcessingTest.SAML_ATTRIBUTE_VALUE,
				samlAttributes.iterator().next());
	}

	/**
	 * Basic test a standard simple signed response.
	 * => using testProcessSaml20AuthnResponseProcessing2()
	 * 
	 * @throws Exception
	 */
	@Test
	public void testSimpleSignedResponseProcessing2() throws Exception {
		SamlResponseData samlResponseData =
				this.testProcessSaml20AuthnResponseProcessing2(this.responseSimpleSigned, SamlBindingEnum.SAML_20_HTTP_POST);

		List<String> samlAttributes = samlResponseData.getAttribute(OpenSaml20ProcessingTest.SAML_ATTRIBUTE_KEY);
		Assert.assertEquals("SAML attributes list size is incorrect !", 1, samlAttributes.size());
		Assert.assertEquals("SAML attribute value is incorrect !", OpenSaml20ProcessingTest.SAML_ATTRIBUTE_VALUE,
				samlAttributes.iterator().next());
	}

	/**
	 * Test of attacked 1 response : Corruption of XML tree.
	 * => using testProcessSaml20AuthnResponseProcessing1()
	 * 
	 * @throws Exception
	 */
	@Test(expected=XMLParserException.class)
	public void testAttacked1ResponseProcessing1() throws Exception {
		// Invalid XML : test cannot load the mock HTTP request => throw a XMLParserException
		SamlResponseData samlResponseData =
				this.testProcessSaml20AuthnResponseProcessing1(this.responseAttacked1, SamlBindingEnum.SAML_20_HTTP_POST);

		List<String> samlAttributes = samlResponseData.getAttribute(OpenSaml20ProcessingTest.SAML_ATTRIBUTE_KEY);
		Assert.assertEquals("SAML attributes list size is incorrect !", 1, samlAttributes.size());
		Assert.assertEquals("SAML attribute value is incorrect !", OpenSaml20ProcessingTest.SAML_ATTRIBUTE_VALUE,
				samlAttributes.iterator().next());
	}

	/**
	 * Test of attacked 1 response : Corruption of XML tree.
	 * => using testProcessSaml20AuthnResponseProcessing2()
	 * 
	 * @throws Exception
	 */
	@Test(expected=MessageDecodingException.class)
	public void testAttacked1ResponseProcessing2() throws Exception {
		// invalid XML : must throw a MessageDecodingException
		this.testProcessSaml20AuthnResponseProcessing2(this.responseAttacked1, SamlBindingEnum.SAML_20_HTTP_POST);
	}

	/**
	 * Test of attacked 2 response : Add an unsigned assertion.
	 * => using testProcessSaml20AuthnResponseProcessing1()
	 * 
	 * @throws Exception
	 */
	@Test(expected=ValidationException.class)
	public void testAttacked2ResponseProcessing1() throws Exception {
		// unsigned assertion : must throw a ValidationException
		this.testProcessSaml20AuthnResponseProcessing1(this.responseAttacked2, SamlBindingEnum.SAML_20_HTTP_POST);
	}

	/**
	 * Test of attacked 2 response : Add an unsigned assertion.
	 * => using testProcessSaml20AuthnResponseProcessing2()
	 * 
	 * @throws Exception
	 */
	@Test(expected=ValidationException.class)
	public void testAttacked2ResponseProcessing2() throws Exception {
		// unsigned assertion : must throw a ValidationException
		this.testProcessSaml20AuthnResponseProcessing2(this.responseAttacked2,  SamlBindingEnum.SAML_20_HTTP_POST);
	}

	/**
	 * Test of processSaml20AuthnResponse() by reading the test xml response file
	 * and building an opensaml tree.
	 * => test the processSaml20AuthnResponse() in isolation.
	 * 
	 * @param samlResponse
	 */
	protected SamlResponseData testProcessSaml20AuthnResponseProcessing1(final Resource responseResource,
			final SamlBindingEnum binding) throws Exception {
		// Load basic SAML Response in OpenSaml objects
		Response samlResponse = (Response)
				this.buildOpenSamlXmlObjectFromResource(responseResource, binding);

		// Perform the test
		final SamlResponseData samlResponseData =
				this.spProcessor.processSaml20AuthnResponse(samlResponse, binding, this.idpConnector);

		Assert.assertNotNull("SAML Response Data is null !", samlResponseData);

		return samlResponseData;
	}

	/**
	 * Test of processSaml20AuthnResponse() by reading the test xml response file
	 * and injecting it in a mock HTTP request. Then using
	 * extractSamlObjectFromRequest() to build an opensaml tree.
	 * => test the extractSamlObjectFromRequest() and processSaml20AuthnResponse().
	 * 
	 * @param samlResponse
	 */
	protected SamlResponseData testProcessSaml20AuthnResponseProcessing2(final Resource responseResource,
			final SamlBindingEnum binding) throws Exception {
		// Load attacked 1 SAML Response in plain text
		String xmlResponse = this.readFile(responseResource);
		String encodedResponse = OpenSamlHelper.httpPostEncode(xmlResponse);
		// Mock a HTTP request containing the SAML Response
		MockHttpServletRequest mockResponse = this.BuildSamlMockResponse(encodedResponse, binding.getHttpMethod());

		// Test the extraction of the response from the HTTP request
		Response opensamlResponse = (Response) this.spProcessor.extractSamlObjectFromRequest(mockResponse, binding);
		Assert.assertNotNull("OpenSaml tree response is null !", opensamlResponse);

		// Perform the test
		final SamlResponseData samlResponseData =
				this.spProcessor.processSaml20AuthnResponse(opensamlResponse, binding, this.idpConnector);

		Assert.assertNotNull("SAML Response Data is null !", samlResponseData);

		return samlResponseData;
	}

	/**
	 * Update the conditions of an assertion to pass the validation.
	 * 
	 * @param samlResponse
	 */
	protected void updateConditionsForValidation(final Response samlResponse) {
		final DateTime now = new DateTime();
		Assertion assertion = samlResponse.getAssertions().iterator().next();
		assertion.getConditions().setNotBefore(now.minus(1000000));
		assertion.getConditions().setNotOnOrAfter(now.plus(1000000));
	}

	/**
	 * Read a Ressource File.
	 * 
	 * @param resourceFile
	 * @param binding
	 * @return the string representation of the file
	 * @throws IOException
	 * @throws SecurityException
	 * @throws MessageDecodingException
	 */
	private XMLObject buildOpenSamlXmlObjectFromResource(final Resource resourceFile, final SamlBindingEnum binding) throws Exception {
		// Parse XML file
		BasicParserPool ppMgr = new BasicParserPool();
		ppMgr.setNamespaceAware(true);
		Document inCommonMDDoc = ppMgr.parse(resourceFile.getInputStream());
		Element rootElement = inCommonMDDoc.getDocumentElement();

		// Get apropriate unmarshaller
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(rootElement);

		// Unmarshall using the document root element, an EntitiesDescriptor in this case
		XMLObject xmlObject = unmarshaller.unmarshall(rootElement);

		Assert.assertNotNull("Unable to read test SAML XML file !", xmlObject);

		return xmlObject;
	}

	/**
	 * Read a Ressource File.
	 * 
	 * @param resourceFile
	 * @return the string representation of the file
	 * @throws IOException
	 */
	private String readFile(final Resource resourceFile) throws IOException {
		return FileUtils.readFileToString(resourceFile.getFile());
	}

	/**
	 * Build a Mock Request representing a SAML Request.
	 * 
	 * @param samlRequest
	 * @return the mock request
	 */
	private MockHttpServletRequest BuildSamlMockRequest(final String samlRequest, final String binding) {
		MockHttpServletRequest request = new MockHttpServletRequest(new MockServletContext(OpenSaml20ProcessingTest.RESOURCE_BASE_PATH));
		request.setMethod(binding);
		request.setParameter("SAMLRequest", samlRequest);
		return request;
	}

	/**
	 * Build a Mock Request representing a SAML Response.
	 * 
	 * @param samlResponse
	 * @return the mock request
	 */
	private MockHttpServletRequest BuildSamlMockResponse(final String samlResponse, final String binding) {
		MockHttpServletRequest request = new MockHttpServletRequest(new MockServletContext(OpenSaml20ProcessingTest.RESOURCE_BASE_PATH));
		request.setMethod(binding);
		request.setParameter("SAMLResponse", samlResponse);
		return request;
	}

	/**
	 * Temp method to sign a response.
	 * 
	 * @param samlResponse
	 * @throws IOException
	 */
	private void signResponse(final Response samlResponse) throws IOException {
		final Assertion assertion = samlResponse.getAssertions().iterator().next();
		Signature signature1 = this.spProcessor.buildSignature(false);
		Signature signature2 = this.spProcessor.buildSignature(false);
		assertion.setSignature(signature1);
		samlResponse.setSignature(signature2);
		OpenSamlHelper.httpPostEncode(assertion);
		OpenSamlHelper.httpPostEncode(samlResponse);
	}

}
