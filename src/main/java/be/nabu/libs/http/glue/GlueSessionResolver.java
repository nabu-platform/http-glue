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

package be.nabu.libs.http.glue;

import java.util.List;
import java.util.Map;

import be.nabu.libs.http.api.server.Session;
import be.nabu.libs.http.api.server.SessionProvider;
import be.nabu.libs.http.api.server.SessionResolver;
import be.nabu.libs.http.core.HTTPUtils;
import be.nabu.utils.mime.api.Header;

public class GlueSessionResolver implements SessionResolver {

	private SessionProvider provider;

	public GlueSessionResolver(SessionProvider provider) {
		this.provider = provider;
	}
	
	@Override
	public Session getSession(Header...headers) {
		Map<String, List<String>> cookies = HTTPUtils.getCookies(headers);
		String originalSessionId = GlueListener.getSessionId(cookies);
		return originalSessionId != null && provider != null ? provider.getSession(originalSessionId) : null;
	}

}
