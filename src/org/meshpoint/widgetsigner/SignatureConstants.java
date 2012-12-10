package org.meshpoint.widgetsigner;
/******************************************************************************
 * Copyright © 2009-2010 Aplix Corporation.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 ******************************************************************************/

public interface SignatureConstants {

	public static String distributorTarget = "#DistributorSignature";
	public static String authorTarget = "#AuthorSignature";
	public static String roleProperty = "dsp:Role";
	public static String identifierProperty = "dsp:Identifier";
	public static String createdProperty = "dsp:Created";
	public static String distributorProfile = "<dsp:Profile\n URI=\"http://www.w3.org/ns/widgets-digsig#profile\" />";
	public static String profileProperty = "dsp:Profile";
	public static String uri = "URI";
	public static String profileURI = "http://www.w3.org/ns/widgets-digsig#profile";
	public static String prefix = "dsp";
	public static String distributorRoleURI = "http://www.w3.org/ns/widgets-digsig#role-distributor";
	public static String authorRoleURI = "http://www.w3.org/ns/widgets-digsig#role-author";
	public static String authorId = "AuthorSignature";
	public static String distributorId = "DistributorSignature";
	public static String signaturePropertiesURI = "http://www.w3.org/2009/xmldsig-properties";
	public static String signaturePropertiesPrefix = "xmlns:dsp";
	public static String profile = "profile";
	public static String identifier = "identifier";
	public static String role = "role";
	public static String created = "created";
	public static String id = "Id";
	public static String colon = ":";
	public static String percent = "%";
	public static String authorFormat = "%a";
	public static String certificateFormat = "%f";
	public static String widgetFormat = "%w";
	public static String hashFormat = "%h";
	public static Object timeFormat = "%t";
	public static String author = "author";
	public static String widget = "widget";
	public static String widgetIdAttribute = "id";
	public static String targetRestriction = "wac:TargetRestriction";
}
