package be.nabu.libs.http.glue.impl;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;

import be.nabu.glue.annotations.GlueParam;
import be.nabu.glue.utils.ScriptRuntime;
import be.nabu.libs.evaluator.annotations.MethodProviderClass;
import be.nabu.libs.http.api.HTTPEntity;
import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.api.HTTPResponse;
import be.nabu.libs.http.api.LinkableHTTPResponse;
import be.nabu.libs.http.core.HTTPUtils;
import be.nabu.libs.resources.URIUtils;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ByteBuffer;
import be.nabu.utils.io.api.ReadableContainer;
import be.nabu.utils.mime.api.ContentPart;
import be.nabu.utils.mime.api.Header;
import be.nabu.utils.mime.impl.FormatException;
import be.nabu.utils.mime.impl.MimeUtils;

@MethodProviderClass(namespace = "request")
public class RequestMethods {
	
	public static final String URL = "url";
	public static final String ENTITY = "entity";
	public static final String GET = "requestGet";
	public static final String POST = "requestPost";
	public static final String COOKIES = "requestCookies";
	public static final String PATH = "requestPath";
	public static final String CONTENT = "content";
	
	public static byte[] content() throws IOException {
		HTTPEntity entity = entity();
		if (entity.getContent() instanceof ContentPart) {
			ReadableContainer<ByteBuffer> readable = ((ContentPart) entity.getContent()).getReadable();
			try {
				return IOUtils.toBytes(readable);
			}
			finally {
				readable.close();
			}
		}
		return null;
	}
	
	public static HTTPEntity entity() {
		return (HTTPEntity) ScriptRuntime.getRuntime().getContext().get(ENTITY);
	}
	
	public static Header header(@GlueParam(name = "name") String name) {
		return entity().getContent() != null
			? MimeUtils.getHeader(name, entity().getContent().getHeaders())
			: null;
	}
	
	public static Header[] headers(@GlueParam(name = "name") String name) {
		if (entity().getContent() == null) {
			return null;
		}
		else if (name == null) {
			return entity().getContent().getHeaders();
		}
		else {
			return MimeUtils.getHeaders(name, entity().getContent().getHeaders());
		}
	}
	
	public static String method() {
		HTTPRequest request = null;
		if (entity() instanceof HTTPRequest) {
			request = (HTTPRequest) entity();
		}
		else if (entity() instanceof LinkableHTTPResponse) {
			request = ((LinkableHTTPResponse) entity()).getRequest();
		}
		return request == null ? null : request.getMethod().toLowerCase();
	}
	
	public static String target() {
		HTTPRequest request = null;
		if (entity() instanceof HTTPRequest) {
			request = (HTTPRequest) entity();
		}
		else if (entity() instanceof LinkableHTTPResponse) {
			request = ((LinkableHTTPResponse) entity()).getRequest();
		}
		return request == null ? null : request.getTarget();
	}
	
	public static Integer code() {
		HTTPResponse response = null;
		if (entity() instanceof HTTPResponse) {
			response = (HTTPResponse) entity();
		}
		return response == null ? null : response.getCode();
	}
	
	public static double version() {
		return entity().getVersion();
	}
	
	/**
	 * If you don't give any parameters, it will get the current URL
	 * If you give it a path, it will build a new URL based on the current URL
	 */
	public static URI url(String path) throws FormatException {
		URI uri = (URI) ScriptRuntime.getRuntime().getContext().get(URL);
		if (uri == null) {
			HTTPRequest request = null;
			if (entity() instanceof HTTPRequest) {
				request = (HTTPRequest) entity();
			}
			else if (entity() instanceof LinkableHTTPResponse) {
				request = ((LinkableHTTPResponse) entity()).getRequest();
			}
			uri = request == null ? null : HTTPUtils.getURI(request, false);
		}
		if (path != null) {
			if (!path.startsWith("/")) {
				path = ServerMethods.root() + path;
			}
			try {
				return new URI(uri.getScheme() + "://" + uri.getAuthority() + URIUtils.encodeURI(path));
			}
			catch (URISyntaxException e) {
				throw new RuntimeException(e);
			}
		}
		else {
			return uri;
		}
	}
	
	@SuppressWarnings("unchecked")
	public static Object cookies(String name) {
		Map<String, List<String>> cookies = (Map<String, List<String>>) ScriptRuntime.getRuntime().getContext().get(RequestMethods.COOKIES);
		return name == null || cookies == null ? cookies : cookies.get(name);
	}
	
	@SuppressWarnings("unchecked")
	public static String cookie(String name) {
		if (name == null) {
			return null;
		}
		List<String> all = (List<String>) cookies(name);
		return all == null || all.isEmpty() ? null : all.get(0);
	}
	
	@SuppressWarnings("unchecked")
	public static Object gets(String name) {
		Map<String, List<String>> get = (Map<String, List<String>>) ScriptRuntime.getRuntime().getContext().get(RequestMethods.GET);
		return name == null || get == null ? get : get.get(name);
	}
	
	@SuppressWarnings("unchecked")
	public static String get(String name) {
		if (name == null) {
			return null;
		}
		List<String> all = (List<String>) gets(name);
		return all == null || all.isEmpty() ? null : all.get(0);
	}
	
	@SuppressWarnings("unchecked")
	public static Object posts(String name) {
		Map<String, List<String>> posts = (Map<String, List<String>>) ScriptRuntime.getRuntime().getContext().get(RequestMethods.POST);
		return name == null || posts == null ? posts : posts.get(name);
	}
	
	@SuppressWarnings("unchecked")
	public static String post(String name) {
		if (name == null) {
			return null;
		}
		List<String> all = (List<String>) posts(name);
		return all == null || all.isEmpty() ? null : all.get(0);
	}
	
	@SuppressWarnings("unchecked")
	public static Object paths(String name) {
		Map<String, String> path = (Map<String, String>) ScriptRuntime.getRuntime().getContext().get(RequestMethods.PATH);
		return name == null || path == null ? path : path.get(name);
	}
	
	@SuppressWarnings("unchecked")
	public static String path(String name) throws FormatException {
		if (name == null) {
			return url(null).getPath();
		}
		List<String> all = (List<String>) paths(name);
		return all == null || all.isEmpty() ? null : all.get(0);
	}
}
