package be.nabu.libs.http.glue.impl;

import be.nabu.libs.http.core.ServerHeader;
import be.nabu.utils.mime.api.Header;
import be.nabu.utils.mime.impl.MimeUtils;

public class GlueHTTPUtils {
	
	public static String getHost(Header...headers) {
		Header header = MimeUtils.getHeader(ServerHeader.REMOTE_HOST.getName(), headers);
		return header == null ? getIp(headers) : header.getValue();
	}
	
	public static String getIp(Header...headers) {
		Header header = MimeUtils.getHeader(ServerHeader.REMOTE_ADDRESS.getName(), headers);
		return header == null ? null : header.getValue();
	}
	
	public static String getUserAgent(Header...headers) {
		Header header = MimeUtils.getHeader("User-Agent", headers);
		if (header == null) {
			return null;
		}
		else {
			StringBuilder builder = new StringBuilder();
			builder.append(header.getValue());
			if (header.getComments() != null) {
				for (String comment : header.getComments()) {
					builder.append("; " + comment);
				}
			}
			return builder.toString();
		}
	}
	
}
