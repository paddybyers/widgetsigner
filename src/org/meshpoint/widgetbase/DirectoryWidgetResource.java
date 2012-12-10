package org.meshpoint.widgetbase;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Hashtable;

public class DirectoryWidgetResource implements IWidgetResource {

	private ArrayList<String> childNames ;
	private Hashtable<String, File> children;
	private File widgetDir;
	public DirectoryWidgetResource(String dir) throws FileNotFoundException {
		init(new File(dir));
	}

	public DirectoryWidgetResource(File dirFile) throws FileNotFoundException {
		init(dirFile);
	}

	private void init(File dirFile) throws FileNotFoundException {
		if(!dirFile.exists()) {
			throw new FileNotFoundException();
		}
		if(!dirFile.isDirectory()) {
			throw new IllegalArgumentException();
		}
		widgetDir = dirFile;
		childNames =  new ArrayList<String>();
		children = new Hashtable<String, File>();
		scanDirectory(dirFile);
	}

	private void scanDirectory(File dirFile){
		File[] childFiles = dirFile.listFiles();
		for(File child : childFiles){
			if(child.isFile()){
				String fileName = getrelativePath(widgetDir, child);
				childNames.add(fileName);
				children.put(fileName, child);
			}
			else {
				scanDirectory(child);
			}
		}
	}

	public boolean contains(String name) {
		return children.containsKey(name);
	}

	public String[] list() {
		String[] s = new String[childNames.size()];
		return childNames.toArray(s);
	}

	public InputStream open(String name) throws FileNotFoundException {
		return new FileInputStream(children.get(name));
	}

	public void dispose() {}

	private String getrelativePath(File base, File path){
		String relative = base.toURI().relativize(path.toURI()).getPath();
		return relative;
	}
}
