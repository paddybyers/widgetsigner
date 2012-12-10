package org.meshpoint.widgetbase;

import java.io.IOException;
import java.io.InputStream;

public interface IWidgetResource {
	public String[] list();
	public boolean contains(String name);
	public InputStream open(String name) throws IOException;
	public void dispose();
}
