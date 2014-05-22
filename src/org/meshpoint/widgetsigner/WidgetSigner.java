package org.meshpoint.widgetsigner;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.TimeZone;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.SignatureProperties;
import org.apache.xml.security.signature.SignatureProperty;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.meshpoint.widgetbase.DirectoryWidgetResource;
import org.meshpoint.widgetbase.IWidgetResource;
import org.meshpoint.widgetbase.ZipWidgetResource;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public final class WidgetSigner {
	//signature type
	private static final int AUTHOR_SIGNATURE = 0;
	private static final int DISTRIBUTOR_SIGNATURE_BASE = 0;

	//default identifier
	private static final String DEFAULT_IDENTIFIER = "%a:%f:%w:%h:%t";

	//name of signature file
	private static final String AUTHOR_SIGNATURE_FILE = "author-signature.xml";
	private static final String DISTRIBUTOR_SIGNATURE_BASE_FILE = "signature%d.xml";

	//error code
	public static final int SUCCEEDED = 0;
	public static final int GEN_ERR = 1;
	public static final int NO_SUCH_FILE = 2;
	public static final int FAILED_TO_OPEN_ZIP_FILE = 3;
	public static final int FAILED_TO_LOAD_KEYSTORE = 4;
	public static final int FAILED_TO_GET_CERTIFICATE = 5;
	public static final int FAILED_TO_GET_PRIVATEKEY = 6;
	public static final int FAILED_TO_GET_CRL = 7;
	public static final int CERTIFICATEEXCEPTION_THROWN = 8;
	public static final int CRLEXCEPTION_THROWN = 9;
	public static final int IOEXCEPTION_THROWN = 10;
	public static final int XMLSIGNATUREEXCEPTION_THROWN = 11;

	private static WidgetSigner signer = null;
	private String error = null;
	private KeyStore ks = null;
	private KeyStore intermediateks = null;
	private X509Certificate cert = null;
	private X509CRL crl = null;
	private PrivateKey privatekey = null;
	private IWidgetResource widget = null;

	private static Provider bcProvider = null;

	private WidgetSigner(){}

	public static WidgetSigner getInstance(){
		return signer;
	}

	public static void main(String[] args) {
		String formatstr = "WidgetSigner -w <widget> -k <keystore> -p <password> -a <alias> -s <signtype> [-i <intermediatekeystore>] [-c] [-d <identifier>] [-IMEI <imei1>,<imei2>,... ] [-MEID <MEID1>,<MEID2>,...] [-r <crl>]";

	    HelpFormatter formatter = new HelpFormatter();
		GnuParser parser =  new GnuParser();
		Options opts = new Options();

		Option opt = new Option("w", "widget", true, "Path of widget to be signed");
		opt.setRequired(true);
		opts.addOption(opt);

		opt = new Option("k", "keystore", true, "Path of PKCS12 keystore used to be sign the widget");
		opt.setRequired(true);
		opts.addOption(opt);

		opt = new Option("p", "passwd", true, "password of end keystore");
		opt.setRequired(true);
		opts.addOption(opt);

		opt = new Option("a", "alias", true, "PrivateKey and Certificate's alias in end keystore");
		opt.setRequired(true);
		opts.addOption(opt);

		opt = new Option("i", "intermediatekeystore", true, "Path of (.jks/.bks) keystore containing intermediate certificates (not password protected)");
		opt.setRequired(false);
		opts.addOption(opt);

		opt = new Option("s", "signtype", true, "0--author signature, 1--distributor signature 1, 2--distributor signature 2, ...");
		opt.setRequired(true);
		opts.addOption(opt);

		opt = new Option("c", "created", false, "add dsp:Created SignatureProperty");
		opt.setRequired(false);
		opts.addOption(opt);

		opt = new Option("d", "identifier", true, "format string for dsp:Identifier SignatureProperty");
		opt.setRequired(false);
		opts.addOption(opt);

		opt = new Option("IMEI", true, "IMEI strings");
		opt.setRequired(false);
		opt.setArgs(25);
		opts.addOption(opt);

		opt = new Option("MEID", true, "MEID strings");
		opt.setRequired(false);
		opt.setArgs(25);
		opts.addOption(opt);

		opt = new Option("r", "crl", true, "Path of CRL to embed in signature");
		opt.setRequired(false);
		opts.addOption(opt);

		CommandLine cli = null;
		try {
			 cli = parser.parse(opts, args);
		} catch (ParseException e) {
			formatter.printHelp(formatstr, opts);
            return;
		}

		WidgetSigner s = WidgetSigner.getInstance();
		int result = s.sign(
			cli.getOptionValue("w"),
			cli.getOptionValue("k"),
			cli.getOptionValue("p"),
			cli.getOptionValue("a"),
			cli.getOptionValue("i"),
			Integer.parseInt(cli.getOptionValue("s")),
			cli.hasOption('c'),
			cli.getOptionValue("d"),
			cli.getOptionValues("IMEI"),
			cli.getOptionValues("MEID"),
			cli.getOptionValue("r")
		);
		
		if(result != SUCCEEDED) {
			System.err.println("Error generating signature: " + s.getErrorMessage());
		}
	}

	public String getErrorMessage(){
		return error;
	}

	public int sign(String widgetPath, String p12FilePath, String passwd, String alias, String intermediateKeystorePath, int signType, boolean created, String identifier, String[] imeis, String[] meids, String crlPath){
		if(widgetPath == null || p12FilePath == null || alias == null || signType < 0){
			error = "widgetPath, p12FilePath, privateKeyAlias, certificateAlias should not be null, signType must >= 0";
			return GEN_ERR;
		}

		File widgetDir = new File(widgetPath);
		if(!widgetDir.exists()){
			error = "Unable to find widget file";
			return NO_SUCH_FILE;
		}

		if(widgetDir.isDirectory()){
			try {
				widget = new DirectoryWidgetResource(widgetPath);
			} catch (FileNotFoundException e) {
				e.printStackTrace();
				error = e.getMessage();
				return NO_SUCH_FILE;
			}
		}
		else {
			try {
				widget = new ZipWidgetResource(widgetPath);
			} catch (FileNotFoundException e) {
				e.printStackTrace();
				error = e.getMessage();
				return NO_SUCH_FILE;
			} catch (ZipException e) {
				e.printStackTrace();
				error = e.getMessage();
				return FAILED_TO_OPEN_ZIP_FILE;
			} catch (IOException e) {
				e.printStackTrace();
				error = e.getMessage();
				return FAILED_TO_OPEN_ZIP_FILE;
			}
		}

		ks = loadP12KeyStore(p12FilePath, passwd);
		if(ks == null){
			error = "Unable to load private keystore";
			return FAILED_TO_LOAD_KEYSTORE;
		}
		cert = getCertificate(ks, alias);
		if(cert == null){
			error = "Unable to locate certificate with alias " + alias + " in keystore";
			return FAILED_TO_GET_CERTIFICATE;
		}

		privatekey = getPrivateKey(ks, alias, passwd);
		if(privatekey == null){
			error = "Unable to locate private key with alias " + alias + " in keystore";
			return FAILED_TO_GET_PRIVATEKEY;
		}

		if(intermediateKeystorePath != null)
			intermediateks = loadintermediateKeyStore(intermediateKeystorePath);
		if(intermediateks == null)
			intermediateks = ks;

		if(identifier == null || identifier.length() <= 0 ){
			identifier = DEFAULT_IDENTIFIER;
		}
		
		if(crlPath != null && crlPath.length() != 0) {
			try {
				FileInputStream fis = new FileInputStream(crlPath);
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				crl = (X509CRL)cf.generateCRL(fis);
				fis.close();
			} catch (FileNotFoundException e) {
				error = "Unable to locate CRL at path " + crlPath;
				return FAILED_TO_GET_CRL;
			} catch (CertificateException e) {
				error = "Certificate exception processing CRL";
				return CERTIFICATEEXCEPTION_THROWN;
			} catch (CRLException e) {
				error = "Certificate exception processing CRL";
				return CRLEXCEPTION_THROWN;
			} catch (IOException e) {
				error = "I/O exception processing CRL";
				return IOEXCEPTION_THROWN;
			}
		}

		int ret = createSignatureXML(widgetPath, signType, created, identifier, imeis, meids);
		return ret;
	}

	private KeyStore loadP12KeyStore(String p12FilePath, String passwd) {
		File certKeyFile = new File(p12FilePath);
		if (certKeyFile != null && certKeyFile.exists()) {
			try {
				KeyStore ks = KeyStore.getInstance("pkcs12", bcProvider);
				ks.load(new FileInputStream(p12FilePath), passwd.toCharArray());
				return ks;
			} catch (KeyStoreException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return null;
	}

	private KeyStore loadintermediateKeyStore(String intermediateKeystorePath){
		File certKeyFile = new File(intermediateKeystorePath);
		if (certKeyFile != null && certKeyFile.exists()) {
			try {
				KeyStore ks = KeyStore.getInstance("bks", bcProvider);
				ks.load(new FileInputStream(intermediateKeystorePath), null);
				return ks;
			} catch (KeyStoreException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return null;
	}

	private X509Certificate[] getCertificateChain(X509Certificate cert){
		ArrayList<X509Certificate> list = new ArrayList<X509Certificate>();
		list.add(cert);
		while((cert = getIssuer(cert)) != null && !isCA(cert)) {
			list.add(cert);
		}
		X509Certificate[] ret = new X509Certificate[list.size()];
		return list.toArray(ret);
	}

	private X509Certificate getIssuer(X509Certificate cert){
		try {
			Enumeration<String> aliases = intermediateks.aliases();
			while(aliases.hasMoreElements()){
				String alias = aliases.nextElement();
				X509Certificate c = (X509Certificate) intermediateks.getCertificate(alias);
				if(c.getSubjectX500Principal().equals(cert.getIssuerX500Principal())){
					return c;
				}
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return null;
	}

	private boolean isCA(X509Certificate cert){
		return cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal());
	}

	private X509Certificate getCertificate(KeyStore ks, String certificateAlias) {
		X509Certificate cert = null;
		try {
			cert = (X509Certificate) ks.getCertificate(certificateAlias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return cert;
	}

	private PrivateKey getPrivateKey(KeyStore ks, String privateKeyAlias, String passwd) {
		PrivateKey pk = null;
		try {
			pk = (PrivateKey) ks.getKey(privateKeyAlias, passwd.toCharArray());
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return pk;
	}

	private int createSignatureXML(String widgetPath, int signType, boolean created, String identifier, String[] imeis, String[] meids) {
		String signFile = null;
		File file = new File(widgetPath);
		String signFileName = (signType == AUTHOR_SIGNATURE) ? AUTHOR_SIGNATURE_FILE :
			String.format(DISTRIBUTOR_SIGNATURE_BASE_FILE, signType - DISTRIBUTOR_SIGNATURE_BASE);

		if(file.isDirectory()){
			signFile = file.getAbsoluteFile() + File.separator + signFileName;
		}
		else {
			signFile = file.getAbsoluteFile().getParentFile().getAbsolutePath() + File.separator + signFileName;
		}

		try {
			Constants.setSignatureSpecNSprefix("");
		} catch (XMLSecurityException e) {
			e.printStackTrace();
			error = e.getMessage();
			return GEN_ERR;
		}

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		DocumentBuilder db = null;
		try {
			db = dbf.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
			error = e.getMessage();
			return GEN_ERR;
		}

		Document doc = db.newDocument();
		XMLSignature xmlsig = null;
		String baseURI = new File(signFile).toURI().toString();
		try {
			if (privatekey.getAlgorithm().equals("RSA")) {
				xmlsig = new XMLSignature(doc, baseURI,
						XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256,
//						Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
						Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
			} else if (privatekey.getAlgorithm().equals("DSA")) {
				xmlsig = new XMLSignature(doc, baseURI,
						XMLSignature.ALGO_ID_SIGNATURE_DSA,
						Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
			}
		} catch (XMLSecurityException e) {
			e.printStackTrace();
			error = e.getMessage();
			return XMLSIGNATUREEXCEPTION_THROWN;
		}

		String sigIdAttribute = (signType == AUTHOR_SIGNATURE) ? SignatureConstants.authorId : SignatureConstants.distributorId;
		xmlsig.getElement().setAttribute("Id", sigIdAttribute);

		doc.appendChild(xmlsig.getElement());

		xmlsig.getSignedInfo().addResourceResolver(new WidgetResourceResolver(widget));

		int err = findDocuments(xmlsig, signType);
		if(err > 0){
			return err;
		}

		try {
			createSignatureProperties(signType, doc, xmlsig, created, identifier);
			Transforms transforms = new Transforms(doc);
			transforms.addTransform(Transforms.TRANSFORM_C14N11_OMIT_COMMENTS);
			xmlsig.addDocument("#prop", transforms, "http://www.w3.org/2001/04/xmlenc#sha256");
		} catch (XMLSignatureException e) {
			e.printStackTrace();
			error = e.getMessage();
			return XMLSIGNATUREEXCEPTION_THROWN;
		} catch (TransformationException e) {
			e.printStackTrace();
			error = e.getMessage();
			return CRLEXCEPTION_THROWN;
		}

		try {
			if (imeis != null || meids != null) {
				createTargetRestriction(signType, doc, xmlsig, imeis, meids);
				Transforms transforms = new Transforms(doc);
				transforms.addTransform(Transforms.TRANSFORM_C14N11_OMIT_COMMENTS);
				xmlsig.addDocument("#target", transforms, "http://www.w3.org/2001/04/xmlenc#sha256");
			}
		} catch (XMLSecurityException e) {
			e.printStackTrace();
			error = e.getMessage();
			return XMLSIGNATUREEXCEPTION_THROWN;
		}

		try {
			X509Data x509Data = new X509Data(doc);
			X509Certificate[] certChain = getCertificateChain(cert);
			for(X509Certificate c : certChain){
				x509Data.addCertificate(c);
			}
			if(crl != null) {
				x509Data.addCRL(crl.getEncoded());
			}
			xmlsig.getKeyInfo().add(x509Data);
		} catch (XMLSecurityException e) {
			e.printStackTrace();
			error = e.getMessage();
			return XMLSIGNATUREEXCEPTION_THROWN;
		} catch (CRLException e) {
			error = e.getMessage();
			return XMLSIGNATUREEXCEPTION_THROWN;
		}

		try {
			xmlsig.sign(privatekey);
		} catch (XMLSignatureException e) {
			e.printStackTrace();
			error = e.getMessage();
			return XMLSIGNATUREEXCEPTION_THROWN;
		}

		java.io.FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(signFile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			error = e.getMessage();
			return NO_SUCH_FILE;
		}

		XMLUtils.outputDOM(doc, fos, true);

		try {
			fos.close();
		} catch (IOException e) {
			e.printStackTrace();
			error = e.getMessage();
			return GEN_ERR;
		}
		
		/* close the underlying widget resource */
		widget.dispose();

		if(file.isFile()){
			File f = new File(signFile);
			try {
				addFilesToExistingZip(file, f);
			} catch (IOException e) {
				e.printStackTrace();
				error = e.getMessage();
				return GEN_ERR;
			}
			f.delete();
		}
		return SUCCEEDED;
	}

	private void createTargetRestriction(int signType, Document doc,
			XMLSignature xmlsig, String[] imeis, String[] meids) throws XMLSecurityException {
		ObjectContainer container = new ObjectContainer(doc);
		container.setId("target");
		container.setXPathNamespaceContext("xmlns:wac",
				"http://wacapps.net/ns/digsig");
		if (imeis != null) {
			for (int idx = 0; idx < imeis.length; idx++) {
				Element targetRestriction = doc
						.createElement(SignatureConstants.targetRestriction);
				targetRestriction.setAttribute("IMEI", imeis[idx]);
				container.appendChild(targetRestriction);
			}
		}

		if (meids != null) {
			for (int idx = 0; idx < meids.length; idx++) {
				Element targetRestriction = doc
						.createElement(SignatureConstants.targetRestriction);
				targetRestriction.setAttribute("MEID", meids[idx]);
				container.appendChild(targetRestriction);
			}
		}
		xmlsig.appendObject(container);
	}

	public static void addFilesToExistingZip(File zipFile, File file) throws IOException {
		/* create a temp file to contain the new zip resource */
		File tempFile = File.createTempFile(zipFile.getName(), null);

		/* copy existing Zip entries to new file */
		byte[] buf = new byte[1024];
		ZipInputStream zin = new ZipInputStream(new FileInputStream(zipFile));
		ZipOutputStream out = new ZipOutputStream(new FileOutputStream(tempFile));
		ZipEntry entry;
		while((entry = zin.getNextEntry()) != null) {
			String name = entry.getName();
			if (!file.getName().equals(name)) {
				// Add ZIP entry to output stream.
				out.putNextEntry(new ZipEntry(name));
				int len;
				while ((len = zin.read(buf)) > 0) {
					out.write(buf, 0, len);
				}
			}
		}
		zin.close();

		/* Add new file entry */
		InputStream in = new FileInputStream(file);
		out.putNextEntry(new ZipEntry(file.getName()));
		int len;
		while ((len = in.read(buf)) > 0) {
			out.write(buf, 0, len);
		}

		/* Complete the entry and Zip file */
		out.closeEntry();
		in.close();
		out.finish();
		out.close();

		/* delete original file and rename */
		boolean updated = zipFile.delete();
		if(updated) {
			updated = tempFile.renameTo(zipFile);
			if(updated)
				return;
		}

		throw new IOException("Unable to update the widget resource: "
					+ zipFile.getAbsolutePath());
	}

	private int findDocuments(XMLSignature signature, int signType) {
		String[] all = widget.list();
		for(String file : all){
			if(signType == AUTHOR_SIGNATURE && file.equals(AUTHOR_SIGNATURE_FILE))
				continue;
			if(isDistributorSignature(file))
				continue;

			try {
				signature.addDocument(file, null, "http://www.w3.org/2001/04/xmlenc#sha256");
			} catch (XMLSignatureException e) {
				e.printStackTrace();
				error = e.getMessage();
				return XMLSIGNATUREEXCEPTION_THROWN;
			}
		}
		return SUCCEEDED;
	}

	private static boolean isDistributorSignature(String name) {
		if(name.startsWith("signature") && name.endsWith(".xml")) {
			String maybeNumber = name.substring(9, name.length()-4);
			char firstDigit = maybeNumber.charAt(0);
			if(firstDigit >= '0' && firstDigit <= '9') {
				for(int i = 1; i < maybeNumber.length(); i++) {
					char digit = maybeNumber.charAt(i);
					if(digit < '0' || digit > '9')
						return false;
				}
				return true;
			}
		}
		return false;
	}

	private ObjectContainer createSignatureProperties(int signType, Document doc, XMLSignature signature, boolean created, String identifier) throws XMLSignatureException {
		String signTypeTarget = (signType == AUTHOR_SIGNATURE)? SignatureConstants.authorTarget : SignatureConstants.distributorTarget;
		String signTypeRoleURI = (signType == AUTHOR_SIGNATURE)? SignatureConstants.authorRoleURI : SignatureConstants.distributorRoleURI;

		ObjectContainer container = new ObjectContainer(doc);
		container.setId("prop");
		SignatureProperties properties = new SignatureProperties(doc);

		/* profile */
		SignatureProperty profileProperty = new SignatureProperty(doc, signTypeTarget);
		profileProperty.setId(SignatureConstants.profile);
		Element profileElement = doc.createElement(SignatureConstants.profileProperty);
		profileElement.setAttribute(SignatureConstants.uri, SignatureConstants.profileURI);
		profileProperty.appendChild(profileElement);
		properties.addSignatureProperty(profileProperty);

		/* role */
		SignatureProperty roleProperty = new SignatureProperty(doc, signTypeTarget);
		roleProperty.setId(SignatureConstants.role);
		Element roleElement = doc.createElement(SignatureConstants.roleProperty);
		roleElement.setAttribute(SignatureConstants.uri, signTypeRoleURI);
		roleProperty.appendChild(roleElement);
		properties.addSignatureProperty(roleProperty);

		/* identifier */
		SignatureProperty identifierProperty = new SignatureProperty(doc, signTypeTarget);
		identifierProperty.setId(SignatureConstants.identifier);
		Element identifierElement = doc.createElement(SignatureConstants.identifierProperty);
		identifierProperty.appendChild(identifierElement);
		String identifierString = "";
		identifierString = generateIdentifierString(identifier, signature);
		identifierElement.setTextContent(identifierString);
		properties.addSignatureProperty(identifierProperty);

		/* created */
		if(created) {
			SignatureProperty createdProperty = new SignatureProperty(doc, signTypeTarget);
			createdProperty.setId(SignatureConstants.created);
			Element createdElement = doc.createElement(SignatureConstants.createdProperty);
			createdElement.setTextContent(getCurrentTime());
			createdProperty.appendChild(createdElement);
			properties.addSignatureProperty(createdProperty);
		}

		/* finish */
		properties.getElement().setAttribute(SignatureConstants.signaturePropertiesPrefix, SignatureConstants.signaturePropertiesURI);
		container.appendChild(properties.getElement());
		signature.appendObject(container);
		return container;
	}

	private String getCurrentTime() {
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
		dateFormat.setTimeZone(TimeZone.getDefault());
		String date = dateFormat.format(new Date());
		SimpleDateFormat timeFormat = new SimpleDateFormat("hh:mm:ss");
		timeFormat.setTimeZone(TimeZone.getDefault());
		String time = timeFormat.format(new Date());
		String finalDateTime = date + "T" +time + "Z";
		timeFormat.format(new Date());
		return finalDateTime;
	}

	private String generateIdentifierString(String identifier, XMLSignature signature) {
		StringBuffer buffer = new StringBuffer();
		for (int i = 0; i < identifier.length(); i++) {
			char ch = identifier.charAt(i);
			if (ch == '%') {
				if (i + 1 < identifier.length()) {
					char formatChar = identifier.charAt(i + 1);
					if (formatChar == 'f' || formatChar == 'a' || formatChar == 'h' || formatChar == 't' || formatChar == 'w') {
						String expandedStr = getExpandedString(formatChar, signature);
						if (expandedStr != null) {
							buffer.append(expandedStr);
						}
						i = i + 1;
					} else {
						buffer.append(ch);
						buffer.append(formatChar);
						i = i + 1;
					}
				} else {
					buffer.append(ch);
				}
			} else {
				buffer.append(ch);
			}
		}
		return buffer.toString();
	}

	private String getExpandedString(char formatChar, XMLSignature signature) {
		Document document = parseConfigFile();
		if (document != null) {
			switch(formatChar) {
			case 'f':
				return appendCertificateHash();
			case 'w':
				return appendWidgetId(document);
			case 't':
				return appendTime();
			case 'a':
				return appendAuthor(document);
			case 'h':
				return appendSignedInfoHash(signature);
			default:
			}
		}
		return null;
	}

	private Document parseConfigFile() {
		if (widget.contains("config.xml")) {
			DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder;
			docBuilderFactory.setValidating(false);
			try {
				docBuilder = docBuilderFactory.newDocumentBuilder();
				Document document = docBuilder.parse(widget.open("config.xml"));
				return document;
			} catch (ParserConfigurationException e) {
				e.printStackTrace();
				return null;
			} catch (SAXException e) {
				e.printStackTrace();
				return null;
			} catch (IOException e) {
				e.printStackTrace();
				return null;
			}
		}
		return null;
	}

	private String appendTime() {
		return getCurrentTime();
	}

	private String appendSignedInfoHash(XMLSignature signature) {
		SignedInfo signedInfo = signature.getSignedInfo();
		Element signedInfoElement = signedInfo.getElement();
		try {
//			Canonicalizer canonicalizer = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
			Canonicalizer canonicalizer = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
			byte[] bytes = canonicalizer.canonicalizeSubtree(signedInfoElement);
			try {
				MessageDigest digest = MessageDigest.getInstance("SHA-256");
				byte[] signedInfoBytes = digest.digest(bytes);
				String signedInfoString = Base64.encode(signedInfoBytes);
				return signedInfoString;
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		} catch (InvalidCanonicalizerException e) {
			e.printStackTrace();
		} catch (CanonicalizationException e) {
			e.printStackTrace();
		}
		return null;
	}

	private String appendWidgetId(Document document) {
		NodeList nodes = document.getElementsByTagName(SignatureConstants.widget);
		if (nodes != null && nodes.getLength() > 0) {
			Node widgetNode = nodes.item(0);
			if (widgetNode != null) {
				if (widgetNode instanceof Element) {
					Element widgetElement = (Element) widgetNode;
					Attr idAttr = widgetElement.getAttributeNode(SignatureConstants.widgetIdAttribute);
					if (idAttr != null) {
						String attrValue = idAttr.getNodeValue();
						return attrValue;
					}
				}
			}
		}
		return null;
	}

	private String appendCertificateHash() {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			String certstring = Base64.encode(digest.digest(cert.getEncoded()));
			return certstring;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}

	private String appendAuthor(Document document) {
		NodeList nodes = document.getElementsByTagName("widget");
		if (nodes != null && nodes.getLength() > 0) {
			Node widgetNode = nodes.item(0);
			if (widgetNode != null) {
				if (widgetNode instanceof Element) {
					Element widgetElement = (Element) widgetNode;
					NodeList authorTags = widgetElement.getElementsByTagName(SignatureConstants.author);
					if (authorTags != null) {
						if (authorTags.getLength() >= 1) {
							Node authorNode = authorTags.item(0);
							if (authorNode != null) {
								String authorText = authorNode.getTextContent();
								return authorText;
							}
						}
					}
				}
			}
		}
		return null;
	}

	static {
		org.apache.xml.security.Init.init();
		signer = new WidgetSigner();

		bcProvider = Security.getProvider("BC");
		if(bcProvider == null) bcProvider = new BouncyCastleProvider();
		System.out.println("BC provider loaded: "+bcProvider.toString());

	}
}
