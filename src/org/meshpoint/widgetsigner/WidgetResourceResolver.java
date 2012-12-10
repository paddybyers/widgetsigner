package org.meshpoint.widgetsigner;

import java.io.IOException;
import java.io.InputStream;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.meshpoint.widgetbase.IWidgetResource;
import org.w3c.dom.Attr;

public class WidgetResourceResolver extends ResourceResolverSpi {
	private IWidgetResource widgetResource = null;
	private String[] widgetItems = null;

	public WidgetResourceResolver(IWidgetResource widgetResource) {
		this.widgetResource = widgetResource;
		widgetItems = widgetResource.list();
	}

	public XMLSignatureInput engineResolve(Attr uri, String BaseURI) throws ResourceResolverException {
		String file = uri.getNodeValue();
		try {
			InputStream is = widgetResource.open(file);
			XMLSignatureInput result = new XMLSignatureInput(is);
			result.setSourceURI(file);
			return result;
		} catch (IOException e) {
			e.printStackTrace();
			throw new ResourceResolverException("generic.EmptyMessage", e, uri, BaseURI);
		}
	}

	public boolean engineCanResolve(Attr uri, String baseURI) {
		String uriNodeValue = uri.getNodeValue();

		if (uriNodeValue.equals("") || uriNodeValue.startsWith("#")) {
			return false;
		}
		for (String f : widgetItems) {
			if (f.equals(uriNodeValue)) {
				return true;
			}
		}
		return false;
	}

	static {
		org.apache.xml.security.Init.init();
	}
}
