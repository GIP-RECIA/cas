/**
 * 
 */
package org.esco.sso.security.saml.opensaml;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.util.Timer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.sso.security.saml.SamlBindingEnum;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public abstract class OpenSamlHelper {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(OpenSamlHelper.class);

	/** Saml HTTP-Redirect binding encoding. */
	private static final String CHAR_ENCODING = "UTF-8";

	/** Char separator for relay state. */
	private static final String RELAY_STATE_SEPARATOR = "$";

	/** Regex matching Relay State Separator char. */
	private static final String RSS = "\\" + OpenSamlHelper.RELAY_STATE_SEPARATOR;

	/** Regex matching all chars except Relay State Separator. */
	private static final String NRSS = "([^" + OpenSamlHelper.RSS + "]+)";

	/** Regex matching a decoded relay state (xxxx)$(xxxx)$(xxxx). */
	private static final String RELAY_STATE_REGEX =
			OpenSamlHelper.NRSS + OpenSamlHelper.RSS + OpenSamlHelper.NRSS
			+ OpenSamlHelper.RSS + OpenSamlHelper.NRSS;

	private static final Pattern RELAY_STATE_PATTERN = Pattern.compile(OpenSamlHelper.RELAY_STATE_REGEX);

	private static IdentifierGenerator idGenerator;

	static {
		try {
			OpenSamlHelper.idGenerator = new SecureRandomIdentifierGenerator();
		} catch (NoSuchAlgorithmException e) {
			OpenSamlHelper.LOGGER.error("Unable to generate random hex string !", e);
		}
	}

	/**
	 * Marshall an opensaml XMLObject.
	 * 
	 * @param xmlObject the XMLObject
	 * @return the marshalled XML.
	 * @throws MarshallingException
	 */
	public static String marshallXmlObject(final XMLObject xmlObject) throws MarshallingException {
		Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(xmlObject);
		Element element = marshaller.marshall(xmlObject);
		StringWriter rspWrt = new StringWriter();
		XMLHelper.writeNode(element, rspWrt);
		String messageXML = rspWrt.toString();

		return messageXML;
	}

	/**
	 * Unmarshall an opensaml XMLObject.
	 * @param xmlObjectQName
	 * @param xmlType
	 * 
	 * @param xmlObject the XMLObject
	 * @return the marshalled XML.
	 * @throws MarshallingException
	 */
	public static XMLObject unmarshallXmlObject(final QName xmlObjectQName, final String messageXML) throws UnmarshallingException {
		XMLObject xmlObject = null;
		try {
			DocumentBuilder docBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
			InputStream in = new ByteArrayInputStream(messageXML.getBytes());
			Document document = docBuilder.parse(in);

			Element element = XMLHelper.constructElement(document, xmlObjectQName);

			Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(xmlObjectQName);
			xmlObject = unmarshaller.unmarshall(element);
		} catch (UnmarshallingException e) {
			throw e;
		} catch (Exception e) {
			OpenSamlHelper.LOGGER.error("Error while parsing xml message !", e);
		}

		return xmlObject;
	}

	/**
	 * Generate the relay state token.
	 * It embbed the IdP config Id and the SAML binding used.
	 * 
	 * @param idpConfigId the IdP config Id
	 * @param binding the binding
	 * @return the relay state
	 */
	public static String generateRelayState(final int idpConfigId, final SamlBindingEnum binding) {
		StringBuilder relayState = new StringBuilder(128);
		// Random chain
		relayState.append(OpenSamlHelper.generateRandomHexString(16));
		// Plus time (ns)
		relayState.append(String.valueOf(System.nanoTime()).substring(5));
		relayState.append(OpenSamlHelper.RELAY_STATE_SEPARATOR);
		// IdP confi Id
		relayState.append(idpConfigId);
		relayState.append(OpenSamlHelper.RELAY_STATE_SEPARATOR);
		// Supported binding
		relayState.append(binding.ordinal());

		return OpenSamlHelper.base64Encode(relayState.toString());
	}

	/**
	 * Extract the IdP config Id from the relay state.
	 * 
	 * @param relayStateEncoded the relay state
	 * @return the IdP config Id
	 */
	public static String extractIdpConfigIdFromRelayState(final String relayStateEncoded) {
		final String idpConfigId = OpenSamlHelper.extractDataFromRelayState(relayStateEncoded, 2);

		Assert.notNull(idpConfigId, "Error : invalid relay state format !");

		return idpConfigId;
	}

	/**
	 * Extract the IdP config Id from the relay state.
	 * 
	 * @param relayStateEncoded the relay state
	 * @return the IdP config Id
	 */
	public static SamlBindingEnum extractBindingFromRelayState(final String relayStateEncoded) {
		SamlBindingEnum binding = null;
		String pos = OpenSamlHelper.extractDataFromRelayState(relayStateEncoded, 3);

		try {
			int ordinal = Integer.valueOf(pos);
			binding = SamlBindingEnum.values()[ordinal];
		} catch (NumberFormatException e) {
			OpenSamlHelper.LOGGER.error("Error : invalid relay state format !", e);
		}

		Assert.notNull(binding, "Error : invalid relay state format !");

		return binding;
	}

	/**
	 * Extract informations from relay state using regexp grouping.
	 * 
	 * @param relayStateEncoded the encoded relay state
	 * @param pos the data position in relay state
	 * @return the informations
	 */
	protected static String extractDataFromRelayState(final String relayStateEncoded, final int pos) {
		String result = null;
		String relayState = OpenSamlHelper.base64Decode(relayStateEncoded);

		Matcher m = OpenSamlHelper.RELAY_STATE_PATTERN.matcher(relayState);
		if (m.find()) {
			result = m.group(pos);
		}
		Assert.notNull(result, "Error : invalid relay state format !");
		return result;
	}

	public static String base64Encode(final String text) {
		String encodedText = Base64.encodeBytes(text.getBytes(), Base64.DONT_BREAK_LINES);

		return encodedText;
	}

	public static String base64Decode(final String text) {
		byte[] decodedText = Base64.decode(text);

		return new String(decodedText);
	}

	public static String cleanupUrl(final String url) {
		if (url == null) {
			return null;
		}

		final int jsessionPosition = url.indexOf(";jsession");

		if (jsessionPosition == -1) {
			return url;
		}

		final int questionMarkPosition = url.indexOf("?");

		if (questionMarkPosition < jsessionPosition) {
			return url.substring(0, url.indexOf(";jsession"));
		}

		return url.substring(0, jsessionPosition)
				+ url.substring(questionMarkPosition);
	}

	/**
	 * @param i
	 * @return
	 */
	public static String generateRandomHexString(final int size) {
		String id = OpenSamlHelper.idGenerator.generateIdentifier(size);

		return id;
	}

	/**
	 * Encode a SAML2 request for the HTTP-POST binding.
	 * 
	 * @param request the request
	 * @return the encoded request
	 * @throws IOException
	 */
	public static String httpPostEncode(final SignableSAMLObject request) throws IOException {
		String base64EncodedRequest = null;
		ByteArrayOutputStream byteArrayOutputStream = null;

		if (request != null) {

			// TODO MBD: Use OpenSaml encoders
			//			VelocityEngine engine = new VelocityEngine();
			//			String templateId = "classpath:/templates/saml2-post-binding.vm";
			//			HTTPPostEncoder postEncoder = new HTTPPostEncoder(engine , templateId);
			//
			//			BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
			//			messageContext.setP;
			//			postEncoder.encode(messageContext);

			try {
				// Now we must build our representation to put into the html form to
				// be submitted to the idp
				Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(request);
				org.w3c.dom.Element authDOM = marshaller.marshall(request);

				//Signing the request
				Signature signature = request.getSignature();
				Assert.notNull(signature, "The request is not signed !");
				Signer.signObject(signature);

				StringWriter rspWrt = new StringWriter();
				XMLHelper.writeNode(authDOM, rspWrt);
				String messageXML = rspWrt.toString();

				byteArrayOutputStream = new ByteArrayOutputStream();

				// Base 64 Encoded Only for HTTP POST binding
				byteArrayOutputStream.write(messageXML.getBytes());
				byteArrayOutputStream.flush();
				base64EncodedRequest = Base64.encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);

				if (OpenSamlHelper.LOGGER.isDebugEnabled()) {
					OpenSamlHelper.LOGGER.debug(String.format("SAML 2.0 Request: %s", messageXML));
					OpenSamlHelper.LOGGER.debug(String.format("Encoded HTTP-POST Request: %s", base64EncodedRequest));
				}
			} catch (MarshallingException e) {
				OpenSamlHelper.LOGGER.error("Error while marshalling SAML 2.0 Request !", e);
			} catch (SignatureException e) {
				OpenSamlHelper.LOGGER.error("Error while signing SAML 2.0 Request !", e);
			} finally {
				if (byteArrayOutputStream != null) {
					byteArrayOutputStream.close();
				}
			}
		}

		return base64EncodedRequest;
	}

	/**
	 * Encode a SAML2 request for the HTTP-redirect binding.
	 * 
	 * @param request the request
	 * @return the encoded request
	 * @throws IOException
	 */
	public static String httpRedirectEncode(final SignableSAMLObject request) throws IOException {
		String urlEncodedRequest = null;
		ByteArrayOutputStream byteArrayOutputStream = null;
		DeflaterOutputStream deflaterOutputStream = null;

		if (request != null) {
			try {
				// Now we must build our representation to put into the html form to
				// be submitted to the idp
				Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(request);
				org.w3c.dom.Element authDOM = marshaller.marshall(request);

				//Signing the request
				Signature signature = request.getSignature();
				Assert.notNull(signature, "The request is not signed !");
				Signer.signObject(signature);

				StringWriter rspWrt = new StringWriter();
				XMLHelper.writeNode(authDOM, rspWrt);
				String messageXML = rspWrt.toString();

				Deflater deflater = new Deflater(Deflater.DEFLATED, true);
				byteArrayOutputStream = new ByteArrayOutputStream();
				deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);

				// Deflated then Base 64 encoded then Url Encoded for HTTP REDIRECT Binding
				deflaterOutputStream.write(messageXML.getBytes());
				deflaterOutputStream.finish();
				deflater.finish();

				String deflatedRequest = Base64.encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);
				urlEncodedRequest = URLEncoder.encode(deflatedRequest, OpenSamlHelper.CHAR_ENCODING);

				if (OpenSamlHelper.LOGGER.isDebugEnabled()) {
					OpenSamlHelper.LOGGER.debug(String.format("SAML 2.0 Request: %s", messageXML));
					OpenSamlHelper.LOGGER.debug(String.format("Encoded HTTP-Redirect Request: %s", urlEncodedRequest));
				}
			} catch (MarshallingException e) {
				OpenSamlHelper.LOGGER.error("Error while marshalling SAML 2.0 Request !", e);
			} catch (SignatureException e) {
				OpenSamlHelper.LOGGER.error("Error while signing SAML 2.0 Request !", e);
			} finally {
				if (byteArrayOutputStream != null) {
					byteArrayOutputStream.close();
				}
				if (deflaterOutputStream != null) {
					deflaterOutputStream.close();
				}
			}
		}

		return urlEncodedRequest;
	}

	/**
	 * Decode a SAML2 anthentication request for the HTTP-redirect binding.
	 * 
	 * @param authnRequest the authn request
	 * @return the encoded request
	 * @throws IOException
	 */
	public static String httpRedirectDecode(final String encodedRequest) throws IOException {
		String inflatedRequest = null;

		ByteArrayInputStream bytesIn = null;
		InflaterInputStream inflater = null;

		byte[] decodedBytes = Base64.decode(encodedRequest);

		try {
			bytesIn = new ByteArrayInputStream(decodedBytes);
			inflater = new InflaterInputStream(bytesIn, new Inflater(true));
			Writer writer = new StringWriter();
			char[] buffer = new char[1024];

			Reader reader = new BufferedReader(
					new InputStreamReader(inflater, "UTF-8"));
			int n;
			while ((n = reader.read(buffer)) != -1) {
				writer.write(buffer, 0, n);
			}

			inflatedRequest = writer.toString();
		} finally {
			if (bytesIn != null) {
				bytesIn.close();
			}
			if (inflater != null) {
				inflater.close();
			}
		}


		return inflatedRequest;
	}


	/**
	 * Build a metadata provider if a metadata resource was provided.
	 * 
	 * @param metadata the metadata resource
	 * @return the metadata provider
	 * @throws MetadataProviderException
	 * @throws XMLParserException
	 */
	public static MetadataProvider buildMetadataProvider(final Resource metadata) throws MetadataProviderException, XMLParserException {
		ResourceBackedMetadataProvider metatdataProvider = null;

		if ((metadata != null) && metadata.exists()) {
			org.opensaml.util.resource.Resource resource = new SpringResourceWrapper(metadata);

			metatdataProvider = new ResourceBackedMetadataProvider(new Timer(), resource);
			StaticBasicParserPool parserPool = new StaticBasicParserPool();
			parserPool.initialize();
			metatdataProvider.setParserPool(parserPool);
			metatdataProvider.initialize();
		}

		return metatdataProvider;
	}

}
