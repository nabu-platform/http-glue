package be.nabu.libs.http.glue.impl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
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

import be.nabu.glue.ScriptRuntime;
import be.nabu.glue.annotations.GlueParam;
import be.nabu.libs.evaluator.annotations.MethodProviderClass;
import be.nabu.libs.http.api.HTTPRequest;
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
import be.nabu.utils.mime.impl.MimeHeader;
import be.nabu.utils.mime.impl.MimeUtils;
import be.nabu.utils.xml.XMLUtils;

@MethodProviderClass(namespace = "response")
public class ResponseMethods {
	
	public static final List<String> allowedTypes = Arrays.asList(MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML);
	public static final String RESPONSE_HEADERS = "responseHeaders";
	public static final String RESPONSE_STREAM = "responseStream";
	public static final String RESPONSE_CODE = "responseCode";
	public static final String RESPONSE_CHARSET = "responseCharset";
	public static final String RESPONSE_DEFAULT_CHARSET = "responseDefaultCharset";
	public static final String RESPONSE_PREFERRED_TYPE = "responsePreferredType";
	
	@SuppressWarnings("unchecked")
	public static Header header(@GlueParam(name = "name") String name, @GlueParam(name = "value") String value) throws ParseException, IOException {
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
		ScriptRuntime.getRuntime().getContext().put(RESPONSE_CODE, code);
	}
	
	@SuppressWarnings({ "unchecked" })
	public static void content(Object response, String contentType) throws IOException, ParseException {
		Charset usedCharset = null;
		if (response == null) {
			// nothing is known about the response, unset
			ScriptRuntime.getRuntime().getContext().put(RESPONSE_STREAM, null);
			removeHeader("Content-Length");
			removeHeader("Content-Type");
			contentType = null;
		}
		else if (response instanceof InputStream) {
			ScriptRuntime.getRuntime().getContext().put(RESPONSE_STREAM, response);
		}
		else if (response instanceof ReadableContainer) {
			ScriptRuntime.getRuntime().getContext().put(RESPONSE_STREAM, IOUtils.toInputStream((ReadableContainer<ByteBuffer>) response));
		}
		else if (response instanceof String) {
			usedCharset = getCharset();
			byte[] bytes = ((String) response).getBytes(usedCharset);
			ScriptRuntime.getRuntime().getContext().put(RESPONSE_STREAM, new ByteArrayInputStream(bytes));
			header("Content-Length", "" + bytes.length);
			// for a string a content type is required, otherwise it is impossible to correctly report the used charset later on (you can update the charset after having set the string content)
			if (contentType == null) {
				contentType = "text/html";
			}
		}
		else if (response instanceof byte[]) {
			ScriptRuntime.getRuntime().getContext().put(RESPONSE_STREAM, new ByteArrayInputStream((byte []) response));
			header("Content-Length", "" + ((byte[]) response).length);
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
			HTTPRequest request = RequestMethods.content();
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
			header("Content-Length", "" + byteArray.length);
		}
		if (contentType != null) {
			if (usedCharset != null) {
				header("Content-Type", contentType + "; charset=" + getCharset().name());
			}
			else {
				header("Content-Type", contentType);
			}
		}
	}
	
	@SuppressWarnings("unchecked")
	public static Header cookie(String key, String value, Date expires, String path, String domain, Boolean secure, Boolean httpOnly) {
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
		ScriptRuntime.getRuntime().getContext().put(RESPONSE_CHARSET, Charset.forName(charset));
	}
	
	static Charset getCharset() {
		Charset charset = (Charset) ScriptRuntime.getRuntime().getContext().get(RESPONSE_CHARSET);
		if (charset == null) {
			charset = (Charset) ScriptRuntime.getRuntime().getContext().get(RESPONSE_DEFAULT_CHARSET);
		}
		return charset;
	}
	
	public static void redirect(String location, Boolean permanent) throws ParseException, IOException {
		ResponseMethods.code(permanent != null && permanent ? 301 : 307);
		ResponseMethods.header("Location", location);
		ServerMethods.abort();
	}
	
	public static void notModified() {
		ResponseMethods.code(304);
		ServerMethods.abort();
	}
	

	@SuppressWarnings("unchecked")
	public static Header cache(
			@GlueParam(name = "maxAge", description = "How long the cache should live, use '0' to indicate that it should not be cached and null to cache indefinately") Long maxAge, 
			@GlueParam(name = "revalidate", description = "Whether or not the cached data should be revalidated", defaultValue = "false") Boolean revalidate, 
			@GlueParam(name = "private", description = "Whether or not the cache is private", defaultValue = "false") Boolean isPrivate) throws ParseException, IOException {
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
