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
