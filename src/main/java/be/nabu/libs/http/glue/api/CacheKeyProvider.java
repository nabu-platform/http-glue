package be.nabu.libs.http.glue.api;

import be.nabu.glue.api.Script;
import be.nabu.libs.authentication.api.Token;
import be.nabu.libs.http.api.HTTPRequest;

public interface CacheKeyProvider {
	public String getAdditionalCacheKey(HTTPRequest request, Token token, Script script);
}
