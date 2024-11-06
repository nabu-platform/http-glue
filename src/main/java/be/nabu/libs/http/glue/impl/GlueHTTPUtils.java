/*
* Copyright (C) 2015 Alexander Verbruggen
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package be.nabu.libs.http.glue.impl;

import be.nabu.libs.http.core.ServerHeader;
import be.nabu.utils.mime.api.Header;
import be.nabu.utils.mime.impl.MimeUtils;

public class GlueHTTPUtils {
	
	public static String getHost(Header...headers) {
		Header header = MimeUtils.getHeader(ServerHeader.REMOTE_HOST.getName(), headers);
		return header == null ? getIp(headers) : header.getValue();
	}
	
	public static Long getPort(Header...headers) {
		Header header = MimeUtils.getHeader(ServerHeader.REMOTE_PORT.getName(), headers);
		return header == null ? null : Long.parseLong(header.getValue());
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
