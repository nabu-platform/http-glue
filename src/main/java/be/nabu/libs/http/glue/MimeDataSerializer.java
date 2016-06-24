package be.nabu.libs.http.glue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.ParseException;

import be.nabu.libs.cache.api.DataSerializer;
import be.nabu.libs.resources.DynamicResource;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.mime.api.Part;
import be.nabu.utils.mime.impl.FormatException;
import be.nabu.utils.mime.impl.MimeFormatter;
import be.nabu.utils.mime.impl.MimeParser;

public class MimeDataSerializer implements DataSerializer<Part> {

	@Override
	public void serialize(Part object, OutputStream output) throws IOException {
		MimeFormatter formatter = new MimeFormatter();
		try {
			formatter.format(object, IOUtils.wrap(output));
		}
		catch (FormatException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public Part deserialize(InputStream input) throws IOException {
		MimeParser parser = new MimeParser();
		try {
			return parser.parse(new DynamicResource(IOUtils.wrap(input), "tmp", "text/plain", true));
		}
		catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public Class<Part> getDataClass() {
		return Part.class;
	}

}
