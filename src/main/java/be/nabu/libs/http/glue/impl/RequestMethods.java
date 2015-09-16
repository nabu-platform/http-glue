package be.nabu.libs.http.glue.impl;

import java.net.URI;
import java.util.List;
import java.util.Map;

import be.nabu.glue.ScriptRuntime;
import be.nabu.glue.annotations.GlueParam;
import be.nabu.libs.evaluator.annotations.MethodProviderClass;
import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.core.HTTPUtils;
import be.nabu.utils.mime.api.Header;
import be.nabu.utils.mime.impl.FormatException;
import be.nabu.utils.mime.impl.MimeUtils;

@MethodProviderClass(namespace = "request")
public class RequestMethods {
	
	public static final String REQUEST = "request";
	public static final String GET = "requestGet";
	public static final String POST = "requestPost";
	public static final String COOKIES = "requestCookies";
	public static final String PATH = "requestPath";
	
	public static HTTPRequest content() {
		return (HTTPRequest) ScriptRuntime.getRuntime().getContext().get(REQUEST);
	}
	
	public static Header header(@GlueParam(name = "name") String name) {
		return content().getContent() != null
			? MimeUtils.getHeader(name, content().getContent().getHeaders())
			: null;
	}
	
	public static Header[] headers(@GlueParam(name = "name") String name) {
		return content().getContent() != null
			? MimeUtils.getHeaders(name, content().getContent().getHeaders())
			: null;
	}
	
	public static String method() {
		return content().getMethod().toLowerCase();
	}
	
	public static String target() {
		return content().getTarget();
	}
	
	public static double version() {
		return content().getVersion();
	}
	
	public static URI url() throws FormatException {
		return HTTPUtils.getURI(content(), false);
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
	public static String path(String name) {
		if (name == null) {
			return null;
		}
		List<String> all = (List<String>) paths(name);
		return all == null || all.isEmpty() ? null : all.get(0);
	}
}
