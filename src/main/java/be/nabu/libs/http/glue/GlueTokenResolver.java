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

import be.nabu.libs.authentication.api.Token;
import be.nabu.libs.http.api.server.AuthenticationHeader;
import be.nabu.libs.http.api.server.Session;
import be.nabu.libs.http.api.server.TokenResolver;
import be.nabu.libs.http.api.server.SessionProvider;
import be.nabu.libs.http.core.HTTPUtils;
import be.nabu.utils.mime.api.Header;

public class GlueTokenResolver implements TokenResolver {

	private SessionProvider provider;
	private String realm;

	public GlueTokenResolver(SessionProvider provider, String realm) {
		this.provider = provider;
		this.realm = realm;
	}
	
	@Override
	public Token getToken(Header...headers) {
		Map<String, List<String>> cookies = HTTPUtils.getCookies(headers);
		String originalSessionId = GlueListener.getSessionId(cookies);
		Session session = originalSessionId != null && provider != null ? provider.getSession(originalSessionId) : null;
		if (session == null) {
			return null;
		}
		Token token = (Token) session.get(GlueListener.buildTokenName(realm));
		if (token == null) {
			AuthenticationHeader authenticationHeader = HTTPUtils.getAuthenticationHeader(headers);
			token = authenticationHeader == null ? null : authenticationHeader.getToken();
		}
		return token;
	}

}
