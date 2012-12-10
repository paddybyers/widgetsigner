package org.meshpoint.widgetbase;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

public class ZipWidgetResource implements IWidgetResource {
	
	/********************
	 * private state
	 ********************/
	
	private File wgtFile;
	private ZipFile zipFile;
	private String[] childNames;
	private Hashtable<String, ZipEntry> children;

	/**********************
	 * public API
	 **********************/
	
	public ZipWidgetResource(String wgt) throws ZipException, IOException {
		init(new File(wgt));
	}
	public ZipWidgetResource(File wgtFile) throws ZipException, IOException {
		init(wgtFile);
	}
	
	public File getWgtFile() {
		return wgtFile;
	}
	
	public ZipFile getZipFile() {
		return zipFile;
	}

	/**********************
	 * private
	 **********************/
	
	private void init(File wgtFile) throws IOException, IOException {
		this.wgtFile = wgtFile;
		if(!wgtFile.exists()) {
			throw new FileNotFoundException();
		}
		if(!wgtFile.isFile()) {
			throw new IllegalArgumentException();
		}
		zipFile = new ZipFile(wgtFile);
		children = new Hashtable<String, ZipEntry>();
		Enumeration<? extends ZipEntry> entries = zipFile.entries();
		while(entries.hasMoreElements()) {
			ZipEntry entry = entries.nextElement();
			if(!entry.isDirectory()) {
				children.put(entry.getName(), entry);
			}
		}
		childNames = children.keySet().toArray(new String[]{});
	}

	/*************************
	 * IWidgetResource methods
	 *************************/

	public boolean contains(String name) {
		return children.containsKey(name);
	}

	public String[] list() {
		return childNames;
	}

	public InputStream open(String name) throws IOException {
		return zipFile.getInputStream(children.get(name));
	}

	public void dispose() {
		if(zipFile != null) {
			try {zipFile.close();} catch(IOException e){}
		}
	}
}
