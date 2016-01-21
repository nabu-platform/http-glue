package be.nabu.libs.http.glue;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.ws.rs.core.MediaType;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.nabu.glue.Main;
import be.nabu.glue.ScriptRuntime;
import be.nabu.glue.ScriptUtils;
import be.nabu.glue.api.AssignmentExecutor;
import be.nabu.glue.api.ExecutionEnvironment;
import be.nabu.glue.api.Executor;
import be.nabu.glue.api.ExecutorGroup;
import be.nabu.glue.api.GroupedScriptRepository;
import be.nabu.glue.api.OutputFormatter;
import be.nabu.glue.api.Script;
import be.nabu.glue.api.ScriptRepository;
import be.nabu.glue.api.StringSubstituterProvider;
import be.nabu.glue.impl.DefaultOptionalTypeProvider;
import be.nabu.glue.impl.SimpleExecutionContext;
import be.nabu.glue.impl.SimpleExecutionEnvironment;
import be.nabu.glue.impl.formatters.SimpleOutputFormatter;
import be.nabu.glue.impl.methods.ScriptMethods;
import be.nabu.glue.impl.providers.SystemMethodProvider;
import be.nabu.glue.types.GlueTypeUtils;
import be.nabu.libs.authentication.api.Authenticator;
import be.nabu.libs.authentication.api.PermissionHandler;
import be.nabu.libs.authentication.api.RoleHandler;
import be.nabu.libs.authentication.api.Token;
import be.nabu.libs.authentication.api.TokenValidator;
import be.nabu.libs.events.api.EventHandler;
import be.nabu.libs.http.HTTPCodes;
import be.nabu.libs.http.HTTPException;
import be.nabu.libs.http.api.ContentRewriter;
import be.nabu.libs.http.api.HTTPEntity;
import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.api.HTTPResponse;
import be.nabu.libs.http.api.LinkableHTTPResponse;
import be.nabu.libs.http.api.server.AuthenticationHeader;
import be.nabu.libs.http.api.server.Session;
import be.nabu.libs.http.api.server.SessionProvider;
import be.nabu.libs.http.core.DefaultHTTPResponse;
import be.nabu.libs.http.core.HTTPUtils;
import be.nabu.libs.http.glue.impl.GlueHTTPFormatter;
import be.nabu.libs.http.glue.impl.RequestMethods;
import be.nabu.libs.http.glue.impl.ResponseMethods;
import be.nabu.libs.http.glue.impl.ServerMethods;
import be.nabu.libs.http.glue.impl.SessionMethods;
import be.nabu.libs.http.glue.impl.UserMethods;
import be.nabu.libs.metrics.api.MetricInstance;
import be.nabu.libs.resources.URIUtils;
import be.nabu.libs.types.DefinedTypeResolverFactory;
import be.nabu.libs.types.api.ComplexType;
import be.nabu.libs.types.api.DefinedType;
import be.nabu.libs.types.binding.api.UnmarshallableBinding;
import be.nabu.libs.types.binding.api.Window;
import be.nabu.libs.types.binding.json.JSONBinding;
import be.nabu.libs.types.binding.xml.XMLBinding;
import be.nabu.libs.types.map.MapTypeGenerator;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ByteBuffer;
import be.nabu.utils.io.api.ReadableContainer;
import be.nabu.utils.mime.api.ContentPart;
import be.nabu.utils.mime.api.Header;
import be.nabu.utils.mime.api.ModifiableHeader;
import be.nabu.utils.mime.api.ModifiablePart;
import be.nabu.utils.mime.impl.FormatException;
import be.nabu.utils.mime.impl.MimeHeader;
import be.nabu.utils.mime.impl.MimeUtils;
import be.nabu.utils.mime.impl.ParsedMimeFormPart;
import be.nabu.utils.mime.impl.PlainMimeContentPart;
import be.nabu.utils.mime.impl.PlainMimeEmptyPart;

/**
 * Important: the csrf protection only works if the user has a session as the token is stored in there.
 * 
 * TODO: XML/JSON incoming support!!
 * TODO: how to limit sizes of file uploads?
 * TODO: bind sessions to remote host for additional safety? 
 * TODO: double check JSESSION ID generation + make sure it is regenerated after login
 * 
 * Note for file uploads, you can request metadata using ":" syntax, for example suppose your file field was called "myFile", you could ask:
 * 
 * @post
 * myFile ?= null
 * @post myFile:filename
 * myFileName ?= null
 * @post myFile:contentType
 * myFileContentType ?= null
 * 
 */
public class GlueListener implements EventHandler<HTTPRequest, HTTPResponse> {

	private MetricInstance metrics;
	public static final String PUBLIC = "public";
	private static final String CSRF_TOKEN = "csrfToken";
	private ScriptRepository repository;
	private String serverPath;
	private ExecutionEnvironment environment;
	private Charset charset = Charset.defaultCharset();
	private boolean allowPathLookup = true;
	private boolean refreshScripts = Boolean.parseBoolean(System.getProperty("glue.refresh", "false"));
	private String extension;
	private SessionProvider sessionProvider;
	public static final String SESSION_COOKIE = "JSESSIONID";
	private Authenticator authenticator;
	private TokenValidator tokenValidator;
	private String preferredContentType = MediaType.APPLICATION_JSON;
	private boolean scanBefore = false;
	private String realm = "default";
	private List<ContentRewriter> contentRewriters = new ArrayList<ContentRewriter>();
	
	private static Logger logger = LoggerFactory.getLogger(GlueListener.class);

	/**
	 * You can toggle this if you always want the user to have a session
	 */
	private boolean alwaysCreateSession = false;
	
	/**
	 * Only enable remember secret on SSL
	 */
	private boolean rememberSecureOnly = false;
	
	private RoleHandler roleHandler;
	
	private PermissionHandler permissionHandler;
	
	/**
	 * Whether or not we should listen to the request for gzip/deflate encoding
	 */
	private boolean allowEncoding = true;
	
	/**
	 * Some headers can be preparsed before injection, for example the "if-modified-since" as they are of little use in their original form
	 */
	private static boolean preparseHeaders = true;
	
	/**
	 * Whether or not to auto-check for csrf
	 * The only reason to turn this off could be for ajax applications but even then it's best to leave it on
	 */
	private boolean addCsrfCheck = true;
	
	/**
	 * Whether or not the scripts have to match by full name or also simple name
	 */
	private boolean requireFullName = true;
	
	private String filePath;
	
	private Map<String, Date> loginBlacklist = new HashMap<String, Date>();
	
	/**
	 * Caches the analysis of a path to speed things up
	 */
	private Map<String, PathAnalysis> pathAnalysis = new HashMap<String, PathAnalysis>();
	
	private List<StringSubstituterProvider> substituterProviders = new ArrayList<StringSubstituterProvider>();
	
	public static GlueListener build(SessionProvider sessionProvider, String serverPath, String...arguments) throws IOException, URISyntaxException {
		return new GlueListener(
			sessionProvider,
			Main.buildRepository(Main.getCharset(arguments), false, arguments), 
			new SimpleExecutionEnvironment(Main.getEnvironmentName(arguments)), 
			serverPath
		);
	}
	
	public GlueListener(SessionProvider sessionProvider, ScriptRepository repository, ExecutionEnvironment environment, String serverPath) {
		this.sessionProvider = sessionProvider;
		this.repository = repository;
		this.environment = environment;
		this.serverPath = serverPath;
	}
	
	public Charset getCharset() {
		return charset;
	}
	public void setCharset(Charset charset) {
		this.charset = charset;
	}

	@SuppressWarnings("unchecked")
	@Override
	public HTTPResponse handle(HTTPRequest request) {
		if (refreshScripts) {
			try {
				repository.refresh();
			}
			catch (IOException e) {
				throw new HTTPException(500, e);
			}
		}
		try {
			URI uri = HTTPUtils.getURI(request, false);
			String path = URIUtils.normalize(uri.getPath());
			// not sure if we want to keep this but it may trigger odd things as the '/' is replaced with a '.' for script lookup
			if (path.contains(".")) {
				return null;
			}
			String context;
			if (!path.startsWith(serverPath)) {
				return null;
			}
			else {
				// if you registered an extension, check that it is present
				if (extension != null) {
					if (!path.endsWith("." + extension)) {
						return null;
					}
					else {
						path = path.substring(0, path.length() - (extension.length() + 1));
					}
				}
				path = path.substring(serverPath.length());
				if (path.startsWith("/")) {
					path = path.substring(1);
				}
				context = path;
				path = path.replace('/', '.');
			}
			if (path.trim().isEmpty()) {
				path = "index";
			}
			Map<String, String> pathParameters = new HashMap<String, String>();
			Script script = repository.getScript(path);
			String scriptPath = path;
			if (script == null && allowPathLookup) {
				// look up the path for a valid script with an "path" annotation
				while (script == null && scriptPath.contains(".")) {
					int index = scriptPath.lastIndexOf('.');
					scriptPath = scriptPath.substring(0, index);
					Script possibleScript = repository.getScript(scriptPath);
					if (possibleScript != null) {
						if (possibleScript.getRoot().getContext().getAnnotations().containsKey("path")) {
							String pathValue = possibleScript.getRoot().getContext().getAnnotations().get("path");
							if (!pathAnalysis.containsKey(pathValue)) {
								pathAnalysis.put(pathValue, analyzePath(pathValue));
							}
							// the +1 is to also skip the "." after the script name
							String remainingPath = path.substring(scriptPath.length() + 1).replace('.', '/');
							Map<String, String> analyze = pathAnalysis.get(pathValue).analyze(remainingPath);
							if (analyze != null) {
								script = possibleScript;
								pathParameters.putAll(analyze);
							}
						}
						break;
					}
				}
			}
			if (script == null) {
				return null;
			}
			// the script is matched on single name
			if (requireFullName && !ScriptUtils.getFullName(script).equals(scriptPath)) {
				return null;
			}
			boolean isPublicScript = script.getRoot().getContext().getAnnotations().containsKey("page")
					|| script.getRepository() instanceof GroupedScriptRepository && PUBLIC.equals(((GroupedScriptRepository) script.getRepository()).getGroup());
			if (!isPublicScript) {
				return null;
			}
			Map<String, List<String>> cookies = HTTPUtils.getCookies(request.getContent().getHeaders());
			// get the original session id to judge whether or not we have to set it later
			String originalSessionId = getSessionId(cookies);
			Session session = originalSessionId != null && sessionProvider != null ? sessionProvider.getSession(originalSessionId) : null;
			if (session == null && alwaysCreateSession) {
				session = sessionProvider.newSession();
			}

			Token token = null;
			// first we try to get the token from the session
			if (session != null && session.get(GlueListener.buildTokenName(realm)) != null) {
				token = (Token) session.get(GlueListener.buildTokenName(realm));
			}
			// if not from session, try to get it from authentication header
			else {
				AuthenticationHeader authenticationHeader = HTTPUtils.getAuthenticationHeader(request);
				token = authenticationHeader == null ? null : authenticationHeader.getToken();
				// if we have a token, set it in the session
				if (token != null) {
					if (session == null) {
						session = sessionProvider.newSession();
					}
					session.set(buildTokenName(realm), token);
				}
			}
			
			// check validity of the token
			if (tokenValidator != null) {
				// if no longer valid, destroy the session, it may contain a lot of token-related data
				// note that if the token was already null, we don't destroy the session, it could be a guest session
				if (token != null && !tokenValidator.isValid(token)) {
					session.destroy();
					originalSessionId = null;
					session = null;
					token = null;
				}
			}
			// check permissions automatically
			if (permissionHandler != null) {
				if (!permissionHandler.hasPermission(token, context, request.getMethod().toLowerCase())) {
					throw new HTTPException(token == null ? 401 : 403, "User '" + (token == null ? Authenticator.ANONYMOUS : token.getName()) + "' does not have permission to '" + request.getMethod().toLowerCase() + "' on: " + context);
				}
			}

			Map<String, Object> input = new HashMap<String, Object>();
			// scan all inputs, check for annotations to indicate what you might want
			@SuppressWarnings("rawtypes")
			Map formParameters = null;
			if (request.getContent() instanceof ParsedMimeFormPart) {
				formParameters = ((ParsedMimeFormPart) request.getContent()).getValues();
				if (formParameters != null && addCsrfCheck) {
					if (originalSessionId == null) {
						logger.warn("Possible CSRF attack: client did not pass in required session id");
						throw new HTTPException(500, "CSRF check failed, no session passed in client");
					}
					else if (formParameters.get(CSRF_TOKEN) == null) {
						logger.warn("Possible CSRF attack: client did not pass in any csrf token");
						throw new HTTPException(500, "CSRF check failed, no csrf token found in client response");
					}
					if (session == null) {
						logger.warn("Possible CSRF attack: client passed in invalid session id");
						throw new HTTPException(500, "CSRF check failed, invalid session id passed in by client");
					}
					else if (session.get(CSRF_TOKEN) == null) {
						logger.warn("Possible CSRF attack: client session valid but does not contain csrf token");
						throw new HTTPException(500, "CSRF check failed, no csrf token in session");
					}
					else if (!session.get(CSRF_TOKEN).equals(((List<?>) formParameters.get(CSRF_TOKEN)).get(0))) {
						logger.warn("Possible CSRF attack: csrf token given by client does not match expected csrf token in session");
						throw new HTTPException(400, "CSRF check failed, csrf token given by client does not match expected csrf token in session");
					}
				}
			}
			else if (request.getContent() != null && "multipart/form-data".equals(MimeUtils.getContentType(request.getContent().getHeaders()))) {
				formParameters = HTTPUtils.getMultipartFormData(request);
			}
			Map<String, List<String>> queryProperties = URIUtils.getQueryProperties(uri);
			
			List<Header> headersToAdd = scanBefore ? scan(request, queryProperties, formParameters, cookies, input, pathParameters, script.getRoot()) : null;
			SimpleExecutionContext executionContext = new SimpleExecutionContext(environment, null, "true".equals(environment.getParameters().get("debug")));
			executionContext.setOutputCurrentLine(false);
			executionContext.setPrincipal(token);
			ScriptRuntime runtime = new ScriptRuntime(script, executionContext, input);
			runtime.addSubstituterProviders(substituterProviders);
			
			// set the context
			runtime.getContext().put(ServerMethods.ROOT_PATH, serverPath);
			runtime.getContext().put(RequestMethods.ENTITY, request);
			runtime.getContext().put(RequestMethods.GET, queryProperties);
			runtime.getContext().put(RequestMethods.POST, formParameters);
			runtime.getContext().put(RequestMethods.COOKIES, cookies);
			runtime.getContext().put(RequestMethods.PATH, pathParameters);
			runtime.getContext().put(UserMethods.AUTHENTICATOR, getAuthenticator());
			runtime.getContext().put(UserMethods.ROLE_HANDLER, getRoleHandler());
			runtime.getContext().put(UserMethods.PERMISSION_HANDLER, getPermissionHandler());
			runtime.getContext().put(UserMethods.SSL_ONLY_SECRET, rememberSecureOnly);
			runtime.getContext().put(UserMethods.REALM, realm);
			runtime.getContext().put(SessionMethods.SESSION_PROVIDER, sessionProvider);
			runtime.getContext().put(ResponseMethods.RESPONSE_PREFERRED_TYPE, preferredContentType);
			runtime.getContext().put(SessionMethods.SESSION, session);
			runtime.getContext().put(UserMethods.LOGIN_BLACKLIST, loginBlacklist);
			runtime.getContext().put(ServerMethods.METRICS, metrics);
			
			if (filePath != null) {
				runtime.getContext().put(SystemMethodProvider.CLI_DIRECTORY, filePath);
			}
			
			// run the script
			StringWriter writer = new StringWriter();
			OutputFormatter buffer = scanBefore ? new SimpleOutputFormatter(writer, false) : new GlueHTTPFormatter(repository, charset, writer);
			runtime.setFormatter(buffer);
			runtime.getContext().put(ResponseMethods.RESPONSE_DEFAULT_CHARSET, charset);
			runtime.run();
			if (runtime.getException() != null) {
				throw new HTTPException(500, runtime.getException());
			}
			
			// the content stream (if any)
			InputStream stream = (InputStream) runtime.getContext().get(ResponseMethods.RESPONSE_STREAM);
			
			// this will contain all the headers set by the user during the run
			List<Header> headers = (List<Header>) runtime.getContext().get(ResponseMethods.RESPONSE_HEADERS);
			if (headers == null) {
				headers = new ArrayList<Header>();
			}
			if (headersToAdd != null) {
				headers.addAll(headersToAdd);
			}
			session = getSession(sessionProvider, runtime); 
			// set a cookie for the session if it's a new session
			if (session != null && !session.getId().equals(originalSessionId)) {
				ModifiableHeader cookieHeader = HTTPUtils.newSetCookieHeader(SESSION_COOKIE, session.getId());
				cookieHeader.addComment("Path=" + serverPath);
				cookieHeader.addComment("HttpOnly");
				headers.add(cookieHeader);
			}
			
			// required headers
			Header contentType = null;
			Header contentLength = null;
			
			for (Header header : headers) {
				if (header.getName().equalsIgnoreCase("Content-Type")) {
					contentType = header;
				}
				else if (header.getName().equalsIgnoreCase("Content-Length")) {
					contentLength = header;
				}
			}
			
			// add caching if necessary
			if (script.getRoot().getContext() != null && script.getRoot().getContext().getAnnotations().containsKey("cache")) {
				String string = script.getRoot().getContext().getAnnotations().get("cache");
				Long maxAge = null;
				Boolean revalidate = null;
				Boolean isPrivate = null;
				if (string != null && !string.trim().isEmpty()) {
					for (String part : string.split("[\\s,]+")) {
						part = part.trim();
						if (part.equals("revalidate")) {
							revalidate = true;
						}
						else if (part.equals("private")) {
							isPrivate = true;
						}
						else if (part.equals(PUBLIC)) {
							isPrivate = false;
						}
						else if (part.matches("[0-9]+")) {
							maxAge = Long.parseLong(part);
						}
					}
				}
				headers.add(buildCacheHeader(maxAge, revalidate, isPrivate));
			}
			
			Charset charset = (Charset) runtime.getContext().get(ResponseMethods.RESPONSE_CHARSET);
			if (charset == null) {
				charset = (Charset) runtime.getContext().get(ResponseMethods.RESPONSE_DEFAULT_CHARSET);
			}
			String stringContent = writer.toString().trim();
			if (addCsrfCheck) {
				int formPosition = getFormPosition(stringContent);
				if (formPosition >= 0) {
					// forcibly create a session if csrf checks are required
					// otherwise it is impossible to perform the csrf check on incoming form data
					if (session == null) {
						session = sessionProvider.newSession();
						ModifiableHeader cookieHeader = HTTPUtils.newSetCookieHeader(SESSION_COOKIE, session.getId());
						cookieHeader.addComment("Path=" + serverPath);
						cookieHeader.addComment("HttpOnly");
						headers.add(cookieHeader);
						runtime.getContext().put(SessionMethods.SESSION, session);
					}
					// remove any previously existing CSRF token
					session.set(CSRF_TOKEN, null);
					stringContent = addCsrfCheck(session, stringContent, formPosition);
				}
			}
			if (!stringContent.isEmpty()) {
				for (ContentRewriter rewriter : contentRewriters) {
					stringContent = rewriter.rewrite(stringContent, contentType == null ? "text/html" : contentType.getValue());
				}
			}
			byte [] byteContent = stringContent.isEmpty() ? null : stringContent.getBytes(charset);
			if (contentType == null) {
				// when streaming content, you must explicitly set the content type
				if (stream != null) {
					throw new HTTPException(500, "No content type set for content stream");
				}
				// we assume html if nothing is set
				headers.add(new MimeHeader("Content-Type", "text/html; charset=" + charset.name()));
			}
			// if it's a textual content type and no charset is set, add it (if possible)
			else if (contentType instanceof ModifiableHeader && isTextualType(contentType.getValue())) {
				// check if there is a charset in there
				boolean hasCharset = false;
				for (String comment : contentType.getComments()) {
					if (comment.trim().toLowerCase().startsWith("charset=")) {
						hasCharset = true;
						break;
					}
				}
				if (!hasCharset) {
					((ModifiableHeader) contentType).addComment("charset=" + charset.name());
				}
			}
			if (contentLength == null) {
				// if there is a stream, we need to go with chunked
				if (stream != null) {
					headers.add(new MimeHeader("Transfer-Encoding", "chunked"));
				}
				else {
					headers.add(new MimeHeader("Content-Length", byteContent == null ? "0" : Integer.valueOf(byteContent.length).toString()));
				}
			}
			ModifiablePart part;
			if (stream != null) {
				part = new PlainMimeContentPart(null, IOUtils.wrap(stream), headers.toArray(new Header[headers.size()]));
			}
			else if (byteContent != null) {
				part = new PlainMimeContentPart(null, IOUtils.wrap(byteContent, true), headers.toArray(new Header[headers.size()]));
			}
			else {
				part = new PlainMimeEmptyPart(null, headers.toArray(new Header[headers.size()]));
			}
			if (allowEncoding && part instanceof ContentPart) {
				HTTPUtils.setContentEncoding(part, request.getContent().getHeaders());
			}
			Integer code = (Integer) runtime.getContext().get(ResponseMethods.RESPONSE_CODE);
			if (code == null) {
				code = 200;
			}
			return new DefaultHTTPResponse(request, code, HTTPCodes.getMessage(code), part);
		}
		catch (Exception e) {
			throw new HTTPException(500, e);	
		}
	}

	public static String buildTokenName(String realm) {
		return UserMethods.TOKEN + "." + realm;
	}
	
	public static PathAnalysis analyzePath(String pathValue) {
		String regex = pathValue.replaceAll("\\{[^/}:\\s]+[\\s]*:[\\s]*([^}\\s]+)[\\s]*\\}", "($1)").replaceAll("\\{[^}/]+\\}", "([^/]+)");
		Pattern pattern = Pattern.compile("\\{([^}]+)\\}");
		Matcher matcher = pattern.matcher(pathValue);
		List<String> pathParameters = new ArrayList<String>();
		while (matcher.find()) {
			pathParameters.add(matcher.group(1).replaceAll("[\\s]*:.*$", ""));
		}
		return new PathAnalysis(regex, pathParameters);
	}

	public static Session getSession(SessionProvider provider, ScriptRuntime runtime) {
		Session session = (Session) runtime.getContext().get(SessionMethods.SESSION);
		if (session == null) {
			HTTPRequest request = null;
			if (runtime.getContext().get(RequestMethods.ENTITY) instanceof HTTPRequest) {
				request = (HTTPRequest) runtime.getContext().get(RequestMethods.ENTITY);
			}
			else if (runtime.getContext().get(RequestMethods.ENTITY) instanceof LinkableHTTPResponse) {
				request = ((LinkableHTTPResponse) runtime.getContext().get(RequestMethods.ENTITY)).getRequest();
			}
			if (request != null) {
				Map<String, List<String>> cookies = HTTPUtils.getCookies(request.getContent().getHeaders());
				String sessionId = GlueListener.getSessionId(cookies);
				if (sessionId != null) {
					if (provider != null) {
						session = provider.getSession(sessionId);
					}
				}
			}
		}
		return session;
	}

	private static int getFormPosition(String stringContent) {
		return stringContent == null ? -1 : stringContent.indexOf("<form");
	}
	
	/**
	 * If a form is detected, this will inject a hidden field to prevent https://en.wikipedia.org/wiki/Cross-site_request_forgery
	 */
	private static String addCsrfCheck(Session session, String stringContent, int offset) {
		if (stringContent != null && !stringContent.isEmpty()) {
			int startIndex = stringContent.indexOf("<form", offset);
			if (startIndex >= 0) {
				int endIndex = stringContent.indexOf('>', startIndex);
				// reuse the token across multiple forms
				String token = (String) (session.get(CSRF_TOKEN) == null ? UUID.randomUUID().toString().replace("-", "") : session.get(CSRF_TOKEN));
				stringContent = stringContent.substring(0, endIndex + 1) + "<input type='hidden' name='" + CSRF_TOKEN + "' value='" + token + "'/>" + stringContent.substring(endIndex + 1);
				session.set(CSRF_TOKEN, token);
				// add to other forms (if multiple)
				return addCsrfCheck(session, stringContent, endIndex + 1);
			}
		}
		return stringContent;
	}

	public static String getSessionId(Map<String, List<String>> cookies) {
		return cookies == null || cookies.get(SESSION_COOKIE) == null || cookies.get(SESSION_COOKIE).isEmpty() ? null : cookies.get(SESSION_COOKIE).get(0);
	}
	
	@SuppressWarnings({ "rawtypes" })
	private List<Header> scan(HTTPRequest request, Map<String, List<String>> queryParameters, Map formParameters, Map<String, List<String>> cookieParameters, Map<String, Object> input, Map<String, String> pathParameters, ExecutorGroup root) throws IOException, ParseException {
		List<Header> headersToSet = new ArrayList<Header>();
		Session session = null;
		if (sessionProvider != null) {
			// first time using the session
			String sessionId = getSessionId(cookieParameters);
			// if there is no header or no corresponding session, we need to create it
			if (sessionId != null) {
				session = sessionProvider.getSession(sessionId);
			}
		}
		for (Executor executor : root.getChildren()) {
			if (executor instanceof AssignmentExecutor && !((AssignmentExecutor) executor).isOverwriteIfExists()) {
				String variableName = ((AssignmentExecutor) executor).getVariableName();
				if (variableName != null && input.get(variableName) == null) {
					input.put(variableName, getValue(repository, charset, request, (AssignmentExecutor) executor, session, queryParameters, formParameters, cookieParameters, pathParameters));
				}
			}
			if (executor instanceof ExecutorGroup) {
				headersToSet.addAll(scan(request, queryParameters, formParameters, cookieParameters, input, pathParameters, (ExecutorGroup) executor));
			}
		}
		return headersToSet;
	}

	@SuppressWarnings("rawtypes")
	public static Object getValue(ScriptRepository repository, Charset charset, HTTPEntity entity, AssignmentExecutor executor, Session session, Map<String, List<String>> queryParameters, Map formParameters, Map<String, List<String>> cookieParameters, Map<String, String> pathParameters) throws IOException {
		String optionalType = executor.getOptionalType();
		String variableName = ((AssignmentExecutor) executor).getVariableName();
		Object value = null;
		// you want specific meta data
		if (executor.getContext().getAnnotations().containsKey("meta")) {
			String string = executor.getContext().getAnnotations().get("meta");
			if (string == null || string.trim().isEmpty()) {
				string = variableName;
			}
			if ("contentType".equals(string)) {
				value = MimeUtils.getContentType(entity.getContent().getHeaders());
			}
			else if ("contentLength".equals(string)) {
				value = MimeUtils.getContentLength(entity.getContent().getHeaders());
			}
			else if ("charset".equals(string)) {
				value = MimeUtils.getCharset(entity.getContent().getHeaders());
			}
			else if ("contentRange".equals(string)) {
				value = MimeUtils.getContentRange(entity.getContent().getHeaders());
			}
			else if ("name".equals(string)) {
				value = MimeUtils.getName(entity.getContent().getHeaders());
			}
			else if ("method".equals(string)) {
				value = RequestMethods.method(); 
			}
			else if ("target".equals(string)) {
				value = RequestMethods.target(); 
			}
			else if ("code".equals(string)) {
				value = ScriptRuntime.getRuntime().getContext().get(ResponseMethods.RESPONSE_CODE);
			}
			else if ("url".equals(string)) {
				try {
					value = RequestMethods.url(); 
				}
				catch (FormatException e) {
					// do nothing
				} 
			}
			else {
				throw new HTTPException(500, "Requesting unknown meta data: " + string);
			}
		}
		else if (executor.getContext().getAnnotations().containsKey("content")) {
			if (entity.getContent() instanceof ContentPart) {
				ReadableContainer<ByteBuffer> readable = ((ContentPart) entity.getContent()).getReadable();
				if (readable != null) {
					// unmarshal the content
					if (optionalType != null) {
						ComplexType type = null;
						try {
							Script script = repository.getScript(optionalType);
							if (script != null) {
								type = GlueTypeUtils.toType(ScriptUtils.getInputs(script), new MapTypeGenerator());
							}
						}
						catch (ParseException e) {
							logger.error("Can not parse script '" + type + "'", e);
						}
						if (type == null) {
							DefinedType resolved = DefinedTypeResolverFactory.getInstance().getResolver().resolve(optionalType);
							if (resolved instanceof ComplexType) {
								type = (ComplexType) resolved;
							}
						}
						if (type == null) {
							throw new IllegalArgumentException("Can not resolve complex type: " + optionalType);
						}
						String contentType = MimeUtils.getContentType(entity.getContent().getHeaders());
						String charsetName = MimeUtils.getCharset(entity.getContent().getHeaders());
						UnmarshallableBinding binding = MediaType.APPLICATION_JSON.equals(contentType)
							? new JSONBinding(type, charset == null ? charset : Charset.forName(charsetName))
							: new XMLBinding(type, charset == null ? charset : Charset.forName(charsetName));
						try {
							value = binding.unmarshal(IOUtils.toInputStream(readable, true), new Window[0]);
						}
						catch (ParseException e) {
							logger.error("Could not parse request data", e);
							throw new HTTPException(400, "Invalid data");
						}  
					}
					// just set the stream
					else {
						value = IOUtils.toInputStream(readable, true);
					}
				}
			}
		}
		else if (executor.getContext().getAnnotations().containsKey("header")) {
			String name = executor.getContext().getAnnotations().get("header");
			if (name == null || name.trim().isEmpty()) {
				name = variableName;
			}
			// if not yet "-" separated, add them based on capitalization
			if (!name.contains("-")) {
				name = name.substring(0, 1) + name.substring(1).replaceAll("([A-Z])", "-$1");
			}
			value = entity.getContent() == null ? null : MimeUtils.getHeader(name, entity.getContent().getHeaders());
			if (value != null && preparseHeaders && name.equalsIgnoreCase("If-Modified-Since")) {
				try {
					value = HTTPUtils.parseDate((String) value);
				}
				catch (ParseException e) {
					logger.error("Invalid 'If-Modified-Since' header: " + value, e);
					// unset the original string value
					value = null;
				}
			}
		}
		else if (executor.getContext().getAnnotations().containsKey("get")) {
			String name = executor.getContext().getAnnotations().get("get");
			if (name == null || name.trim().isEmpty()) {
				name = variableName;
			}
			if (queryParameters != null) {
				value = fromParameters(queryParameters, name);
			}
		}
		else if (executor.getContext().getAnnotations().containsKey("post")) {
			String name = executor.getContext().getAnnotations().get("post");
			if (name == null || name.trim().isEmpty()) {
				name = variableName;
			}
			if (formParameters != null) {
				String part = null;
				if (name.contains(":")) {
					part = name.replaceAll("^.+:", "");
					name = name.replaceAll(":.+", "");
				}
				value = fromParameters(formParameters, name);
				// it's a multipart form
				if (value instanceof ContentPart) {
					if ("fileName".equals(part)) {
						value = MimeUtils.getName(((ContentPart) value).getHeaders());
					}
					else if ("contentType".equals(part)) {
						value = MimeUtils.getContentType(((ContentPart) value).getHeaders());
					}
					else {
						ReadableContainer<ByteBuffer> readable = ((ContentPart) value).getReadable();
						DefaultOptionalTypeProvider.wrapDefault(optionalType);
						if ("bytes".equals(optionalType)) {
							value = IOUtils.toBytes(readable);
						}
						// default types will be autoconverted (or at least tried) from string
						else if (DefaultOptionalTypeProvider.wrapDefault(optionalType) != null) {
							String reportedCharset = MimeUtils.getCharset(((ContentPart) value).getHeaders());
							charset = reportedCharset == null ? Charset.defaultCharset() : Charset.forName(reportedCharset);
							value = IOUtils.toString(IOUtils.wrapReadable(readable, charset));
						}
						// just put the bytes there
						else {
							value = IOUtils.toInputStream(readable, true);
						}
					}
				}
			}
		}
		else if (executor.getContext().getAnnotations().containsKey("cookie")) {
			String name = executor.getContext().getAnnotations().get("cookie");
			if (name == null || name.trim().isEmpty()) {
				name = variableName;
			}
			if (cookieParameters != null) {
				value = fromParameters(cookieParameters, name);
			}
		}
		else if (executor.getContext().getAnnotations().containsKey("session")) {
			String name = executor.getContext().getAnnotations().get("session");
			if (name == null || name.trim().isEmpty()) {
				name = variableName;
			}
			value = session == null ? null : session.get(name);
		}
		else if (executor.getContext().getAnnotations().containsKey("path")) {
			String name = executor.getContext().getAnnotations().get("path");
			if (name == null || name.trim().isEmpty()) {
				name = variableName;
			}
			value = pathParameters == null ? null : pathParameters.get(name);
		}
		else {
			// try from the GET
			if (queryParameters != null) {
				value = fromParameters(queryParameters, variableName);
			}
			// try from POST
			if (value == null && formParameters != null) {
				value = fromParameters(formParameters, variableName);
			}
			// try from headers
			if (value == null) {
				String headerName = variableName.replaceAll("([A-Z])", "-$1");
				if (headerName.startsWith("-")) {
					headerName = headerName.substring(1);
				}
				Header header = MimeUtils.getHeader(headerName, entity.getContent().getHeaders());
				if (header != null) {
					value = header.getValue();
				}
			}
		}
		return value;
	}
	
	@SuppressWarnings("rawtypes")
	private static Object fromParameters(Map parameters, String variableName) {
		if (parameters.containsKey(variableName)) {
			if (((List<?>) parameters.get(variableName)).size() == 1) {
				return ((List<?>) parameters.get(variableName)).get(0);
			}
			else {
				return ScriptMethods.array(((List<?>) parameters.get(variableName)).toArray());
			}
		}
		return null;
	}

	public boolean isRefreshScripts() {
		return refreshScripts;
	}

	public void setRefreshScripts(boolean refreshScripts) {
		this.refreshScripts = refreshScripts;
	}

	public Authenticator getAuthenticator() {
		return authenticator;
	}

	public void setAuthenticator(Authenticator authenticator) {
		this.authenticator = authenticator;
	}

	public String getPreferredContentType() {
		return preferredContentType;
	}

	public void setPreferredContentType(String preferredContentType) {
		this.preferredContentType = preferredContentType;
	}
	
	public static boolean isTextualType(String contentType) {
		contentType = contentType.trim().toLowerCase();
		// check for text matches
		return contentType.matches("text/[^;]+")
			// this checks both application/xml and derivatives like "application/atom+xml"
			|| contentType.matches("application/[^;]*xml")
			// json and derivatives
			|| contentType.matches("application/[^;]*json");
	}

	public boolean isAllowEncoding() {
		return allowEncoding;
	}

	public void setAllowEncoding(boolean allowEncoding) {
		this.allowEncoding = allowEncoding;
	}

	public static boolean isPreparseHeaders() {
		return preparseHeaders;
	}

	public static void setPreparseHeaders(boolean preparseHeaders) {
		GlueListener.preparseHeaders = preparseHeaders;
	}

	public ScriptRepository getRepository() {
		return repository;
	}

	public RoleHandler getRoleHandler() {
		return roleHandler;
	}

	public void setRoleHandler(RoleHandler roleHandler) {
		this.roleHandler = roleHandler;
	}

	public boolean isRememberSecureOnly() {
		return rememberSecureOnly;
	}

	public String getFilePath() {
		return filePath;
	}

	public void setFilePath(String filePath) {
		this.filePath = filePath;
	}
	
	public static class PathAnalysis {
		// the regex you can use to extract the groups
		private String regex;
		// the parameter names in order of the capturing groups
		private List<String> parameters;
		private Pattern pattern;
		
		public PathAnalysis(String regex, List<String> parameters) {
			this.regex = regex;
			this.parameters = parameters;
			this.pattern = Pattern.compile(regex);
		}

		public Map<String, String> analyze(String remainingPath) {
			Matcher matcher = pattern.matcher(remainingPath);
			Map<String, String> values = new HashMap<String, String>();
			if (matcher.find()) {
				if (matcher.end() != remainingPath.length()) {
					return null;
				}
				for (int i = 0; i < matcher.groupCount(); i++) {
					values.put(parameters.get(i), matcher.group(i + 1));
				}
			}
			else {
				return null;
			}
			return values;
		}

		public String getRegex() {
			return regex;
		}

		public List<String> getParameters() {
			return parameters;
		}
	}

	public PermissionHandler getPermissionHandler() {
		return permissionHandler;
	}

	public void setPermissionHandler(PermissionHandler permissionHandler) {
		this.permissionHandler = permissionHandler;
	}

	public String getRealm() {
		return realm;
	}

	public void setRealm(String realm) {
		this.realm = realm;
	}
	
	public static Header buildCacheHeader(Long maxAge, Boolean revalidate, Boolean isPrivate) {
		// this indicates that it should not be cached
		if (maxAge != null && maxAge == 0) {
			return new MimeHeader("Cache-Control", "no-store, no-cache");
		}
		else {
			// the cache headers are explained clearly here: https://developers.google.com/web/fundamentals/performance/optimizing-content-efficiency/http-caching?hl=en
			List<String> values = new ArrayList<String>();
			if (maxAge != null) {
				values.add("max-age=" + maxAge);
			}
			if (revalidate != null && revalidate) {
				values.add("no-cache");
				values.add("must-revalidate");
			}
			if (isPrivate != null && isPrivate) {
				values.add("private");
			}
			else {
				values.add(PUBLIC);
			}
			StringBuilder builder = new StringBuilder();
			for (int i = 0; i < values.size(); i++) {
				if (i > 0) {
					builder.append(", ");
				}
				builder.append(values.get(i));
			}
			return new MimeHeader("Cache-Control", builder.toString());
		}
	}

	public TokenValidator getTokenValidator() {
		return tokenValidator;
	}

	public void setTokenValidator(TokenValidator tokenValidator) {
		this.tokenValidator = tokenValidator;
	}

	public SessionProvider getSessionProvider() {
		return sessionProvider;
	}

	public List<ContentRewriter> getContentRewriters() {
		return contentRewriters;
	}

	public boolean isAlwaysCreateSession() {
		return alwaysCreateSession;
	}

	public void setAlwaysCreateSession(boolean alwaysCreateSession) {
		this.alwaysCreateSession = alwaysCreateSession;
	}

	public List<StringSubstituterProvider> getSubstituterProviders() {
		return substituterProviders;
	}
	
	public void blacklistLogin(String ip, Date until) {
		synchronized(loginBlacklist) {
			if (until == null || until.before(new Date())) {
				loginBlacklist.remove(ip);
			}
			else {
				loginBlacklist.put(ip, until);
			}
		}
	}

	public MetricInstance getMetrics() {
		return metrics;
	}

	public void setMetrics(MetricInstance metrics) {
		this.metrics = metrics;
	}
}
