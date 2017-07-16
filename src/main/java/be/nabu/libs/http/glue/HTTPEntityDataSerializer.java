package be.nabu.libs.http.glue;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.ParseException;

import be.nabu.libs.cache.api.DataSerializer;
import be.nabu.libs.http.api.HTTPEntity;
import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.api.HTTPResponse;
import be.nabu.libs.http.core.DefaultDynamicResourceProvider;
import be.nabu.libs.http.core.HTTPFormatter;
import be.nabu.libs.http.core.HTTPParser;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ByteBuffer;
import be.nabu.utils.io.api.ReadableContainer;
import be.nabu.utils.mime.impl.FormatException;

public class HTTPEntityDataSerializer implements DataSerializer<HTTPEntity> {

	@Override
	public void serialize(HTTPEntity response, OutputStream output) throws IOException {
		HTTPFormatter formatter = new HTTPFormatter();
		try {
			if (response instanceof HTTPRequest) {
				formatter.formatRequest((HTTPRequest) response, IOUtils.wrap(output));
			}
			else {
				formatter.formatResponse((HTTPResponse) response, IOUtils.wrap(output));
			}
		}
		catch (FormatException e) {
			throw new RuntimeException(e);
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public HTTPEntity deserialize(InputStream input) throws IOException {
		HTTPParser parser = new HTTPParser(new DefaultDynamicResourceProvider(), false);
		try {
			ReadableContainer<ByteBuffer> bytes = IOUtils.wrap(new BufferedInputStream(input));
			// we check the first three bytes, if it is a number, it is the return code of the server and as such a response, otherwise it is a request
			byte [] buffer = new byte[5];
			long read = bytes.read(IOUtils.wrap(buffer, false));

			// this should not occur
			if (read != 5) {
				throw new IOException("Could not read 5 bytes to determine the entity type");
			}
			
			// we re-append the bytes we read for correct parsing
			bytes = IOUtils.chain(true, IOUtils.wrap(buffer, true), bytes);
			
			// if it's a number, we have a response
			if (new String(buffer, "ASCII").equals("HTTP/")) {
				return parser.parseResponse(bytes);
			}
			else {
				return parser.parseRequest(bytes, null);
			}
		}
		catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public Class<HTTPEntity> getDataClass() {
		return HTTPEntity.class;
	}

}
