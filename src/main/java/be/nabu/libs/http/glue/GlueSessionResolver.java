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
