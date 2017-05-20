package be.nabu.libs.http.glue;

import be.nabu.glue.api.Script;
import be.nabu.libs.authentication.api.Device;
import be.nabu.libs.authentication.api.Token;
import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.api.HTTPResponse;

public interface GlueScriptCallValidator {
	public HTTPResponse validate(HTTPRequest request, Token token, Device device, Script script);
}
