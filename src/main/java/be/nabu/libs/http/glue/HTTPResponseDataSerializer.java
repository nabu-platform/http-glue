package be.nabu.libs.http.glue;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.ParseException;

import be.nabu.libs.cache.api.DataSerializer;
import be.nabu.libs.http.api.HTTPResponse;
import be.nabu.libs.http.core.DefaultDynamicResourceProvider;
import be.nabu.libs.http.core.HTTPFormatter;
import be.nabu.libs.http.core.HTTPParser;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.mime.impl.FormatException;

public class HTTPResponseDataSerializer implements DataSerializer<HTTPResponse> {

	@Override
	public void serialize(HTTPResponse response, OutputStream output) throws IOException {
		HTTPFormatter formatter = new HTTPFormatter();
		try {
			formatter.formatResponse(response, IOUtils.wrap(output));
		}
		catch (FormatException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public HTTPResponse deserialize(InputStream input) throws IOException {
		HTTPParser parser = new HTTPParser(new DefaultDynamicResourceProvider(), false);
		try {
			return parser.parseResponse(IOUtils.wrap(new BufferedInputStream(input)));
		}
		catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public Class<HTTPResponse> getDataClass() {
		return HTTPResponse.class;
	}

}
