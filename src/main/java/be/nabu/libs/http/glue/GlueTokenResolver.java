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
		AuthenticationHeader authenticationHeader = HTTPUtils.getAuthenticationHeader(headers);
		Token token = authenticationHeader == null ? null : authenticationHeader.getToken();
		if (token == null) {
			Map<String, List<String>> cookies = HTTPUtils.getCookies(headers);
			String originalSessionId = GlueListener.getSessionId(cookies);
			Session session = originalSessionId != null && provider != null ? provider.getSession(originalSessionId) : null;
			token = (Token) session.get(GlueListener.buildTokenName(realm));
		}
		return token;
	}

}
