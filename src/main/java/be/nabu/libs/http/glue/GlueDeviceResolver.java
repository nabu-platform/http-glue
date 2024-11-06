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

import be.nabu.libs.authentication.api.Device;
import be.nabu.libs.http.api.server.DeviceResolver;
import be.nabu.utils.mime.api.Header;

public class GlueDeviceResolver implements DeviceResolver {

	private String realm;

	public GlueDeviceResolver(String realm) {
		this.realm = realm;
	}
	
	@Override
	public Device getDevice(Header... headers) {
		return GlueListener.getDevice(realm, headers);
	}

}
