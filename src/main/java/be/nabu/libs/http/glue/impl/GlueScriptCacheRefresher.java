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

package be.nabu.libs.http.glue.impl;

import java.io.IOException;

import be.nabu.libs.cache.api.Cache;
import be.nabu.libs.cache.api.CacheRefresher;
import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.glue.GlueListener;

public class GlueScriptCacheRefresher implements CacheRefresher {

	private GlueListener listener;
	private String cacheName;

	public GlueScriptCacheRefresher(GlueListener listener, String cacheName) {
		this.listener = listener;
		this.cacheName = cacheName;
	}
	
	@Override
	public Object refresh(Object key) throws IOException {
		// we attempt to retrieve the request from the cache
		if (listener.getCacheProvider() != null) {
			Cache cache = listener.getCacheProvider().get(cacheName);
			if (cache != null) {
				// if it is a request, retain it so we still have it for refresh of the response
				if (((String) key).startsWith("request==")) {
					return cache.get(key);
				}
				else {
					HTTPRequest request = (HTTPRequest) cache.get("request==" + key);
					if (request != null) {
						return listener.handle(request, true);
					}
				}
			}
		}
		return null;
	}

	public GlueListener getListener() {
		return listener;
	}

	public void setListener(GlueListener listener) {
		this.listener = listener;
	}

}
