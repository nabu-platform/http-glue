package be.nabu.libs.http.glue;

import java.io.InputStream;
import java.io.StringWriter;
import java.net.URI;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import be.nabu.glue.api.ExecutionEnvironment;
import be.nabu.glue.api.Script;
import be.nabu.glue.api.ScriptRepository;
import be.nabu.glue.impl.SimpleExecutionContext;
import be.nabu.glue.utils.ScriptRuntime;
import be.nabu.libs.authentication.api.Authenticator;
import be.nabu.libs.authentication.api.Token;
import be.nabu.libs.authentication.api.TokenValidator;
import be.nabu.libs.events.api.EventHandler;
import be.nabu.libs.http.HTTPException;
import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.api.server.AuthenticationHeader;
import be.nabu.libs.http.api.server.Session;
import be.nabu.libs.http.api.server.SessionProvider;
import be.nabu.libs.http.core.DefaultHTTPRequest;
import be.nabu.libs.http.core.HTTPUtils;
import be.nabu.libs.http.glue.impl.GlueHTTPFormatter;
import be.nabu.libs.http.glue.impl.RequestMethods;
import be.nabu.libs.http.glue.impl.ResponseMethods;
import be.nabu.libs.http.glue.impl.ServerMethods;
import be.nabu.libs.http.glue.impl.SessionMethods;
import be.nabu.libs.http.glue.impl.UserMethods;
import be.nabu.libs.resources.URIUtils;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.mime.api.Header;
import be.nabu.utils.mime.api.ModifiablePart;
import be.nabu.utils.mime.impl.MimeHeader;
import be.nabu.utils.mime.impl.PlainMimeContentPart;
import be.nabu.utils.mime.impl.PlainMimeEmptyPart;

public class GluePreprocessListener implements EventHandler<HTTPRequest, HTTPRequest> {

	private ScriptRepository repository;
	private boolean refresh;
	private SessionProvider sessionProvider;
	private TokenValidator tokenValidator;
	private String realm;
	private ExecutionEnvironment environment;
	private String serverPath;
	private String preferredResponseType;
	private Charset charset = Charset.defaultCharset();
	private Authenticator authenticator;

	public GluePreprocessListener(Authenticator authenticator, SessionProvider sessionProvider, ScriptRepository repository, ExecutionEnvironment environment, String serverPath) {
		this.authenticator = authenticator;
		this.repository = repository;
		this.environment = environment;
		this.sessionProvider = sessionProvider;
		this.serverPath = serverPath;
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public HTTPRequest handle(HTTPRequest request) {
		try {
			if (refresh) {
				repository.refresh();
			}
			
			URI uri = HTTPUtils.getURI(request, false);
			String path = URIUtils.normalize(uri.getPath()).replaceFirst("^[/]+", "");
			Script preprocessScript = null;
			// we search for a preprocess script on the path somewhere
			while (path.contains("/") && !path.isEmpty()) {
				path = path.replaceAll("/[^/]*$", "");
				if (path.contains(".")) {
					return null;
				}
				preprocessScript = repository.getScript(path.replace('/', '.') + ".preprocess");
				if (preprocessScript != null) {
					break;
				}
			}
			// use the default one
			if (preprocessScript == null) {
				preprocessScript = repository.getScript("preprocess");
			}
			// still no script, just stop
			if (preprocessScript == null) {
				return null;
			}
			
			// get the cookies
			Map<String, List<String>> cookies = HTTPUtils.getCookies(request.getContent().getHeaders());
			// get the query properties
			Map<String, List<String>> queryProperties = URIUtils.getQueryProperties(uri);
			
			String originalSessionId = GlueListener.getSessionId(cookies);
			// get the session
			Session session = originalSessionId != null && sessionProvider != null ? sessionProvider.getSession(originalSessionId) : null;
			
			// get the token
			Token token = null;
			// first we try to get the token from the session
			if (session != null && session.get(GlueListener.buildTokenName(realm)) != null) {
				token = (Token) session.get(GlueListener.buildTokenName(realm));
			}
			// if not from session, try to get it from authentication header
			else {
				AuthenticationHeader authenticationHeader = HTTPUtils.getAuthenticationHeader(request);
				token = authenticationHeader == null ? null : authenticationHeader.getToken();
			}
			
			Token invalidToken = null;
			// check validity of the token
			if (token != null && tokenValidator != null && !tokenValidator.isValid(token)) {
				invalidToken = token;
				// don't use the session
				if (session != null) {
					session = null;
				}
				// or the token
				token = null;
			}

			Map<String, Object> input = new HashMap<String, Object>();
			SimpleExecutionContext executionContext = new SimpleExecutionContext(environment, null, "true".equals(environment.getParameters().get("debug")));
			executionContext.setOutputCurrentLine(false);
			executionContext.setPrincipal(token);
			
			ScriptRuntime runtime = new ScriptRuntime(preprocessScript, executionContext, input);
			
			runtime.getContext().put(ServerMethods.ROOT_PATH, serverPath);
			runtime.getContext().put(RequestMethods.ENTITY, request);
			runtime.getContext().put(RequestMethods.GET, queryProperties);
			runtime.getContext().put(RequestMethods.POST, new HashMap<String, List<String>>());
			runtime.getContext().put(RequestMethods.COOKIES, cookies);
			runtime.getContext().put(RequestMethods.PATH, new HashMap<String, List<String>>());
			runtime.getContext().put(UserMethods.AUTHENTICATOR, authenticator);
			runtime.getContext().put(UserMethods.ROLE_HANDLER, null);
			runtime.getContext().put(UserMethods.PERMISSION_HANDLER, null);
			runtime.getContext().put(UserMethods.SSL_ONLY_SECRET, true);
			runtime.getContext().put(UserMethods.REALM, realm);
			runtime.getContext().put(SessionMethods.SESSION_PROVIDER, sessionProvider);
			runtime.getContext().put(ResponseMethods.RESPONSE_PREFERRED_TYPE, preferredResponseType == null ? "text/html" : preferredResponseType);
			runtime.getContext().put(SessionMethods.SESSION, session);
			runtime.getContext().put(ResponseMethods.RESPONSE_DEFAULT_CHARSET, charset);
			runtime.getContext().put(UserMethods.INVALID_TOKEN, invalidToken);

			// set the original data
			runtime.getContext().put(ResponseMethods.RESPONSE_HEADERS, request.getContent() == null ? new ArrayList<Header>() : new ArrayList<Header>(Arrays.asList(request.getContent().getHeaders())));
			runtime.getContext().put(ResponseMethods.RESPONSE_METHOD, request.getMethod());
			runtime.getContext().put(ResponseMethods.RESPONSE_TARGET, request.getTarget());
			runtime.getContext().put(ResponseMethods.RESPONSE_EMPTY, request.getContent() == null);
			
			StringWriter writer = new StringWriter();
			runtime.setFormatter(new GlueHTTPFormatter(repository, charset, writer));
			runtime.run();
			
			String writtenContent = writer.toString();
			Charset charset = (Charset) runtime.getContext().get(ResponseMethods.RESPONSE_CHARSET);
			if (charset == null) {
				charset = getCharset();
			}
			
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
			else if (!writtenContent.isEmpty()) {
				part = new PlainMimeContentPart(null, IOUtils.wrap(writtenContent.getBytes(charset), true), headers.toArray(new Header[headers.size()]));
			}
			else if (responseIsEmpty || request.getContent() == null) {
				part = new PlainMimeEmptyPart(null, headers.toArray(new Header[headers.size()]));
			}
			else {
				// use the original part
				part = request.getContent();
				// but rewrite the headers
				for (Header header : part.getHeaders()) {
					part.removeHeader(header.getName());
				}
				Session newSession = (Session) runtime.getContext().get(SessionMethods.SESSION);
				// if we have a session but it is not in the request, add it
				if (newSession != null && (originalSessionId == null || !originalSessionId.equals(newSession.getId()))) {
					part.setHeader(new MimeHeader("Cookie", GlueListener.SESSION_COOKIE + "=" + newSession.getId()));
				}
				part.setHeader(headers.toArray(new Header[headers.size()]));
			}
			String method = (String) runtime.getContext().get(ResponseMethods.RESPONSE_METHOD);
			String target = (String) runtime.getContext().get(ResponseMethods.RESPONSE_TARGET);
			
			Boolean responseChanged = (Boolean) runtime.getContext().get(ResponseMethods.RESPONSE_CHANGED);
			if (responseChanged == null) {
				responseChanged = false;
			}
			responseChanged |= !writtenContent.isEmpty();
			
			return responseChanged ? new DefaultHTTPRequest(
				method == null ? request.getMethod() : method, 
				target == null ? request.getTarget() : target, 
				part,
				request.getVersion()
			) : null;
		}
		catch (Exception e) {
			throw new HTTPException(500, e);
		}
	}

	public TokenValidator getTokenValidator() {
		return tokenValidator;
	}

	public void setTokenValidator(TokenValidator tokenValidator) {
		this.tokenValidator = tokenValidator;
	}

	public String getRealm() {
		return realm;
	}

	public void setRealm(String realm) {
		this.realm = realm;
	}

	public boolean isRefresh() {
		return refresh;
	}

	public void setRefresh(boolean refresh) {
		this.refresh = refresh;
	}

	public String getPreferredResponseType() {
		return preferredResponseType;
	}

	public void setPreferredResponseType(String preferredResponseType) {
		this.preferredResponseType = preferredResponseType;
	}

	public Charset getCharset() {
		return charset;
	}

	public void setCharset(Charset charset) {
		this.charset = charset;
	}

}
