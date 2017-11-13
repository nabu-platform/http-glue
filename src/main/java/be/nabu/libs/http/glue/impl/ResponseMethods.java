package be.nabu.libs.http.glue.impl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MediaType;

import org.w3c.dom.Document;

import be.nabu.glue.annotations.GlueParam;
import be.nabu.glue.impl.TransactionalCloseable;
import be.nabu.glue.utils.ScriptRuntime;
import be.nabu.libs.evaluator.annotations.MethodProviderClass;
import be.nabu.libs.http.api.HTTPEntity;
import be.nabu.libs.http.api.HTTPResponse;
import be.nabu.libs.http.core.HTTPUtils;
import be.nabu.libs.http.glue.GlueListener;
import be.nabu.libs.types.ComplexContentWrapperFactory;
import be.nabu.libs.types.api.ComplexContent;
import be.nabu.libs.types.binding.api.MarshallableBinding;
import be.nabu.libs.types.binding.json.JSONBinding;
import be.nabu.libs.types.binding.xml.XMLBinding;
import be.nabu.libs.types.xml.XMLContent;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ByteBuffer;
import be.nabu.utils.io.api.ReadableContainer;
import be.nabu.utils.mime.api.Header;
import be.nabu.utils.mime.api.ModifiableHeader;
import be.nabu.utils.mime.api.ModifiablePart;
import be.nabu.utils.mime.impl.FormatException;
import be.nabu.utils.mime.impl.MimeHeader;
import be.nabu.utils.mime.impl.MimeUtils;
import be.nabu.utils.xml.XMLUtils;

@MethodProviderClass(namespace = "response")
public class ResponseMethods {
	
	public static Boolean ABSOLUTE = Boolean.parseBoolean(System.getProperty("be.nabu.glue.redirect.absolute", "false"));
	public static final List<String> allowedTypes = Arrays.asList(MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML);
	public static final String RESPONSE_HEADERS = "responseHeaders";
	public static final String RESPONSE_STREAM = "responseStream";
	public static final String RESPONSE_PART = "responsePart";
	public static final String RESPONSE_CHARSET = "responseCharset";
	public static final String RESPONSE_DEFAULT_CHARSET = "responseDefaultCharset";
	public static final String RESPONSE_PREFERRED_TYPE = "responsePreferredType";
	
	/**
	 * Specifically for creating a http response
	 */
	public static final String RESPONSE_CODE = "responseCode";
	
	/**
	 * Specifically for rewriting
	 */
	public static final String RESPONSE_TARGET = "responseTarget";
	public static final String RESPONSE_METHOD = "responseMethod";
	public static final String RESPONSE_EMPTY = "responseEmpty";
	
	public static final String RESPONSE_CHANGED = "responseChanged";
	
	/**
	 * If you only pass in the header name, it will simply be removed
	 */
	@SuppressWarnings("unchecked")
	public static Header header(@GlueParam(name = "name") String name, @GlueParam(name = "value") String value, @GlueParam(name = "removeExisting", defaultValue = "true") Boolean removeExisting) throws ParseException, IOException {
		ScriptRuntime.getRuntime().getContext().put(RESPONSE_CHANGED, true);
		if (removeExisting == null || removeExisting) {
			removeHeader(name);
		}
		if (value != null) {
			// the value in this case can include some comments, so parse it
			Header header = MimeHeader.parseHeader(name + ": " + value);
			List<Header> headers = (List<Header>) ScriptRuntime.getRuntime().getContext().get(RESPONSE_HEADERS);
			if (headers == null) {
				headers = new ArrayList<Header>();
				ScriptRuntime.getRuntime().getContext().put(RESPONSE_HEADERS, headers);
			}
			headers.add(header);
			return header;
		}
		return null;
	}
	
	public static void target(@GlueParam(name = "target", defaultValue = "/") String target) {
		ScriptRuntime.getRuntime().getContext().put(RESPONSE_CHANGED, true);
		if (target == null) {
			target = "/";
		}
		ScriptRuntime.getRuntime().getContext().put(RESPONSE_TARGET, target);
	}
	
	public static void method(@GlueParam(name = "method", defaultValue = "GET") String method) {
		ScriptRuntime.getRuntime().getContext().put(RESPONSE_CHANGED, true);
		if (method == null) {
			method = "GET";
		}
		ScriptRuntime.getRuntime().getContext().put(RESPONSE_METHOD, method);
	}
	
	@SuppressWarnings("unchecked")
	private static void removeHeader(String name) {
		List<Header> headers = (List<Header>) ScriptRuntime.getRuntime().getContext().get(RESPONSE_HEADERS);
		if (headers != null) {
			for (int i = headers.size() - 1; i >= 0; i--) {
				if (headers.get(i).getName().equalsIgnoreCase(name)) {
					headers.remove(i);
				}
			}
		}
	}
	
	public static void code(Integer code) {
		ScriptRuntime.getRuntime().getContext().put(RESPONSE_CHANGED, true);
		ScriptRuntime.getRuntime().getContext().put(RESPONSE_CODE, code);
	}
	
	@SuppressWarnings({ "unchecked" })
	public static void content(Object response, String contentType) throws IOException, ParseException {
		ScriptRuntime.getRuntime().getContext().put(RESPONSE_CHANGED, true);
		Charset usedCharset = null;
		if (response == null) {
			ScriptRuntime.getRuntime().getContext().put(RESPONSE_EMPTY, true);
			// nothing is known about the response, unset
			ScriptRuntime.getRuntime().getContext().put(RESPONSE_STREAM, null);
			removeHeader("Content-Length");
			removeHeader("Content-Type");
			contentType = null;
		}
		else if (response instanceof ModifiablePart) {
			ScriptRuntime.getRuntime().getContext().put(RESPONSE_PART, response);
		}
		else if (response instanceof HTTPResponse) {
			ScriptRuntime.getRuntime().getContext().put(RESPONSE_PART, ((HTTPResponse) response).getContent());
			code(((HTTPResponse) response).getCode());
		}
		else if (response instanceof InputStream) {
			// IMPORTANT: There was an issue with the stream being set as content being closed by the time it was used for the response (this ended up in 0-byte downloads)
			// this was because the evaluateexecutor automatically added the stream as a transactioncloseable
			// so we need to remove the transactionable!
			ScriptRuntime.getRuntime().removeTransactionable(new TransactionalCloseable((Closeable) response));
			ScriptRuntime.getRuntime().getContext().put(RESPONSE_STREAM, response);
		}
		else if (response instanceof ReadableContainer) {
			// see above for reason
			ScriptRuntime.getRuntime().removeTransactionable(new TransactionalCloseable((Closeable) response));
			ScriptRuntime.getRuntime().getContext().put(RESPONSE_STREAM, IOUtils.toInputStream((ReadableContainer<ByteBuffer>) response));
		}
		else if (response instanceof String) {
			usedCharset = getCharset();
			byte[] bytes = ((String) response).getBytes(usedCharset);
			ScriptRuntime.getRuntime().getContext().put(RESPONSE_STREAM, new ByteArrayInputStream(bytes));
			header("Content-Length", "" + bytes.length, true);
			// for a string a content type is required, otherwise it is impossible to correctly report the used charset later on (you can update the charset after having set the string content)
			if (contentType == null) {
				contentType = "text/html";
			}
		}
		else if (response instanceof byte[]) {
			ScriptRuntime.getRuntime().getContext().put(RESPONSE_STREAM, new ByteArrayInputStream((byte []) response));
			header("Content-Length", "" + ((byte[]) response).length, true);
		}
		else if (response != null) {
			// if you responded with an array, wrap it
			if (response instanceof Object[]) {
				Map<String, Object> root = new HashMap<String, Object>();
				root.put("anonymous", response);
				response = root;
			}
			if (response instanceof Document) {
				// there is more logic to automatically detect types from maps
				response = XMLUtils.toMap(((Document) response).getDocumentElement());
			}
			// undefined xml content
			else if (response instanceof XMLContent) {
				response = XMLUtils.toMap(((XMLContent) response).getElement());
			}
			if (!(response instanceof ComplexContent)) {
				response = ComplexContentWrapperFactory.getInstance().getWrapper().wrap(response);
				if (response == null) {
					throw new IllegalArgumentException("Can not marshal the object");
				}
			}
			usedCharset = getCharset();
			// given that we are in a primarily website-driven world, use json as default
			HTTPEntity request = RequestMethods.entity();
			if (contentType == null) {
				List<String> acceptedTypes = MimeUtils.getAcceptedContentTypes(request.getContent().getHeaders());
				acceptedTypes.retainAll(allowedTypes);
				contentType = acceptedTypes.isEmpty() 
					? (String) ScriptRuntime.getRuntime().getContext().get(RESPONSE_PREFERRED_TYPE)
					: acceptedTypes.get(0);
			}
			if (!allowedTypes.contains(contentType)) {
				throw new IOException("The requested content type '" + contentType + "' is not supported");
			}
			MarshallableBinding binding = MediaType.APPLICATION_JSON.equals(contentType) 
				? new JSONBinding(((ComplexContent) response).getType(), usedCharset)
				: new XMLBinding(((ComplexContent) response).getType(), usedCharset);
			if (binding instanceof JSONBinding) {
				((JSONBinding) binding).setIgnoreRootIfArrayWrapper(true);
			}
			ByteArrayOutputStream output = new ByteArrayOutputStream();
			binding.marshal(output, (ComplexContent) response);
			byte[] byteArray = output.toByteArray();
			ScriptRuntime.getRuntime().getContext().put(RESPONSE_STREAM, new ByteArrayInputStream(byteArray));
			header("Content-Length", "" + byteArray.length, true);
		}
		if (contentType != null) {
			if (usedCharset != null) {
				header("Content-Type", contentType + "; charset=" + getCharset().name(), true);
			}
			else {
				header("Content-Type", contentType, true);
			}
		}
	}
	
	@SuppressWarnings("unchecked")
	public static Header cookie(String key, String value, Date expires, String path, String domain, Boolean secure, Boolean httpOnly) {
		ScriptRuntime.getRuntime().getContext().put(RESPONSE_CHANGED, true);
		ModifiableHeader header = HTTPUtils.newSetCookieHeader(key, value, expires, path, domain, secure, httpOnly);
		List<Header> headers = (List<Header>) ScriptRuntime.getRuntime().getContext().get(ResponseMethods.RESPONSE_HEADERS);
		if (headers == null) {
			headers = new ArrayList<Header>();
			ScriptRuntime.getRuntime().getContext().put(ResponseMethods.RESPONSE_HEADERS, headers);
		}
		headers.add(header);
		return header;
	}
	
	public static void charset(String charset) {
		ScriptRuntime.getRuntime().getContext().put(RESPONSE_CHANGED, true);
		ScriptRuntime.getRuntime().getContext().put(RESPONSE_CHARSET, Charset.forName(charset));
	}
	
	static Charset getCharset() {
		Charset charset = (Charset) ScriptRuntime.getRuntime().getContext().get(RESPONSE_CHARSET);
		if (charset == null) {
			charset = (Charset) ScriptRuntime.getRuntime().getContext().get(RESPONSE_DEFAULT_CHARSET);
		}
		return charset;
	}
	
	public static void redirect(@GlueParam(name = "location") String location, @GlueParam(name = "permanent") Boolean permanent, @GlueParam(name = "code") Integer code) throws ParseException, IOException, FormatException {
		ScriptRuntime.getRuntime().getContext().put(RESPONSE_CHANGED, true);
		// response code 302 is dubious, some clients do the new call with the original method, some don't (nodejs in particular does not)
		// response code 303 and 307 were added to distinguish clearly between the two
		// where 303 means: if it was a post (or any non-get), change it to a get
		// and 307 means: do the exact same call again
		if (code == null) {
			code = permanent != null && permanent ? 301 : ("get".equalsIgnoreCase(RequestMethods.method()) ? 307 : 303);
		}
		ResponseMethods.code(code);
		// in RFC https://tools.ietf.org/html/rfc2616#section-14.30 it states that location has to be absolute
		// however in RFC https://tools.ietf.org/html/rfc7231#section-7.1.2 which superceeds the previous RFC, it states that the location can be relative
		// the latter RFC is active since mid-2014
		if (ABSOLUTE) {
			ResponseMethods.header("Location", location.startsWith("http://") || location.startsWith("https://") ? location : RequestMethods.url(location).toString(), true);
		}
		else {
			ResponseMethods.header("Location", location, true);
		}
		ServerMethods.abort();
	}
	
	public static void notModified() {
		ScriptRuntime.getRuntime().getContext().put(RESPONSE_CHANGED, true);
		ResponseMethods.code(304);
		ServerMethods.abort();
	}
	
	@SuppressWarnings("unchecked")
	public static Header cache(
			@GlueParam(name = "maxAge", description = "How long the cache should live, use '-1' to indicate that it should not be cached and null or 0 to cache indefinately") Long maxAge, 
			@GlueParam(name = "revalidate", description = "Whether or not the cached data should be revalidated", defaultValue = "false") Boolean revalidate, 
			@GlueParam(name = "private", description = "Whether or not the cache is private", defaultValue = "false") Boolean isPrivate) throws ParseException, IOException {
		ScriptRuntime.getRuntime().getContext().put(RESPONSE_CHANGED, true);
		Header header = GlueListener.buildCacheHeader(maxAge, revalidate, isPrivate);
		List<Header> headers = (List<Header>) ScriptRuntime.getRuntime().getContext().get(RESPONSE_HEADERS);
		if (headers == null) {
			headers = new ArrayList<Header>();
			ScriptRuntime.getRuntime().getContext().put(RESPONSE_HEADERS, headers);
		}
		headers.add(header);
		return header;
	}
}
