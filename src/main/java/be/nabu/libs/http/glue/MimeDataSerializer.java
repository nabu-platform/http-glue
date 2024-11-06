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
