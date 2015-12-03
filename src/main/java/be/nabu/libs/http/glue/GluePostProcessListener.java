package be.nabu.libs.http.glue;

import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import be.nabu.glue.ScriptRuntime;
import be.nabu.glue.api.ExecutionEnvironment;
import be.nabu.glue.api.Script;
import be.nabu.glue.api.ScriptRepository;
import be.nabu.glue.impl.SimpleExecutionContext;
import be.nabu.libs.events.api.EventHandler;
import be.nabu.libs.http.HTTPCodes;
import be.nabu.libs.http.HTTPException;
import be.nabu.libs.http.api.HTTPResponse;
import be.nabu.libs.http.core.DefaultHTTPResponse;
import be.nabu.libs.http.glue.impl.GlueHTTPFormatter;
import be.nabu.libs.http.glue.impl.RequestMethods;
import be.nabu.libs.http.glue.impl.ResponseMethods;
import be.nabu.libs.http.glue.impl.ServerMethods;
import be.nabu.libs.http.glue.impl.SessionMethods;
import be.nabu.libs.http.glue.impl.UserMethods;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.mime.api.Header;
import be.nabu.utils.mime.api.ModifiablePart;
import be.nabu.utils.mime.impl.MimeUtils;
import be.nabu.utils.mime.impl.PlainMimeContentPart;
import be.nabu.utils.mime.impl.PlainMimeEmptyPart;

public class GluePostProcessListener implements EventHandler<HTTPResponse, HTTPResponse> {

	private ScriptRepository repository;
	private ExecutionEnvironment environment;
	private String serverPath;
	private boolean refresh;
	private Charset charset = Charset.defaultCharset();
	private String realm;
	private String preferredResponseType;

	public GluePostProcessListener(ScriptRepository repository, ExecutionEnvironment environment, String serverPath) {
		this.repository = repository;
		this.environment = environment;
		this.serverPath = serverPath;
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public HTTPResponse handle(HTTPResponse response) {
		try {
			if (refresh) {
				repository.refresh();
			}
			
			Script postprocessScript = repository.getScript("postprocess");
			// no script, just stop
			if (postprocessScript == null) {
				return null;
			}
			
			Map<String, Object> input = new HashMap<String, Object>();
			SimpleExecutionContext executionContext = new SimpleExecutionContext(environment, null, "true".equals(environment.getParameters().get("debug")));
			executionContext.setOutputCurrentLine(false);
			
			ScriptRuntime runtime = new ScriptRuntime(postprocessScript, executionContext, input);
			
			runtime.getContext().put(ServerMethods.ROOT_PATH, serverPath);
			runtime.getContext().put(RequestMethods.ENTITY, response);
			runtime.getContext().put(RequestMethods.GET, new HashMap<String, List<String>>());
			runtime.getContext().put(RequestMethods.POST, new HashMap<String, List<String>>());
			runtime.getContext().put(RequestMethods.COOKIES, new HashMap<String, List<String>>());
			runtime.getContext().put(RequestMethods.PATH, new HashMap<String, List<String>>());
			runtime.getContext().put(UserMethods.AUTHENTICATOR, null);
			runtime.getContext().put(UserMethods.ROLE_HANDLER, null);
			runtime.getContext().put(UserMethods.PERMISSION_HANDLER, null);
			runtime.getContext().put(UserMethods.SSL_ONLY_SECRET, true);
			runtime.getContext().put(UserMethods.REALM, realm);
			runtime.getContext().put(SessionMethods.SESSION_PROVIDER, null);
			runtime.getContext().put(ResponseMethods.RESPONSE_PREFERRED_TYPE, preferredResponseType == null ? (response.getContent() == null ? "text/html" : MimeUtils.getContentType(response.getContent().getHeaders())) : preferredResponseType);
			runtime.getContext().put(SessionMethods.SESSION, null);
			runtime.getContext().put(ResponseMethods.RESPONSE_DEFAULT_CHARSET, charset);

			// set the original data
			runtime.getContext().put(ResponseMethods.RESPONSE_HEADERS, response.getContent() == null ? new ArrayList<Header>() : new ArrayList<Header>(Arrays.asList(response.getContent().getHeaders())));
			runtime.getContext().put(ResponseMethods.RESPONSE_EMPTY, response.getContent() == null);
			runtime.getContext().put(ResponseMethods.RESPONSE_CODE, response.getCode());
			
			StringWriter writer = new StringWriter();
			runtime.setFormatter(new GlueHTTPFormatter(repository, charset, writer));
			
			runtime.run();

			// get the headers
			List<Header> headers = (List<Header>) runtime.getContext().get(ResponseMethods.RESPONSE_HEADERS);
			if (headers == null) {
				headers = new ArrayList<Header>();
			}
			// if no new content is set, use original content unless explicitly set to null
			Boolean responseIsEmpty = (Boolean) runtime.getContext().get(ResponseMethods.RESPONSE_EMPTY);
			InputStream stream = (InputStream) runtime.getContext().get(ResponseMethods.RESPONSE_STREAM);
			ModifiablePart part;
			if (stream != null) {
				part = new PlainMimeContentPart(null, IOUtils.wrap(stream), headers.toArray(new Header[headers.size()]));
			}
			else if (responseIsEmpty || response.getContent() == null) {
				part = new PlainMimeEmptyPart(null, headers.toArray(new Header[headers.size()]));
			}
			else {
				// use the original part
				part = response.getContent();
				// but rewrite the headers
				for (Header header : part.getHeaders()) {
					part.removeHeader(header.getName());
				}
				part.setHeader(headers.toArray(new Header[headers.size()]));
			}
			Integer code = (Integer) runtime.getContext().get(ResponseMethods.RESPONSE_CODE);
			if (code == null) {
				code = 200;
			}
			return new DefaultHTTPResponse(
				code,
				HTTPCodes.getMessage(code),
				part,
				response.getVersion()
			);
		}
		catch (Exception e) {
			throw new HTTPException(500, e);
		}
	}

	public boolean isRefresh() {
		return refresh;
	}

	public void setRefresh(boolean refresh) {
		this.refresh = refresh;
	}

	public Charset getCharset() {
		return charset;
	}

	public void setCharset(Charset charset) {
		this.charset = charset;
	}

	public String getRealm() {
		return realm;
	}

	public void setRealm(String realm) {
		this.realm = realm;
	}

	public String getPreferredResponseType() {
		return preferredResponseType;
	}

	public void setPreferredResponseType(String preferredResponseType) {
		this.preferredResponseType = preferredResponseType;
	}

}
