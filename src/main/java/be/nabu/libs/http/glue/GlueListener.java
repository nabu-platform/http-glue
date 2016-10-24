package be.nabu.libs.http.glue;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
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
import be.nabu.glue.OptionalTypeProviderFactory;
import be.nabu.glue.api.AssignmentExecutor;
import be.nabu.glue.api.ExecutionEnvironment;
import be.nabu.glue.api.Executor;
import be.nabu.glue.api.ExecutorGroup;
import be.nabu.glue.api.OutputFormatter;
import be.nabu.glue.api.Script;
import be.nabu.glue.api.ScriptRepository;
import be.nabu.glue.api.StringSubstituterProvider;
import be.nabu.glue.core.api.GroupedScriptRepository;
import be.nabu.glue.core.api.OptionalTypeConverter;
import be.nabu.glue.core.impl.DefaultOptionalTypeProvider;
import be.nabu.glue.core.impl.methods.ScriptMethods;
import be.nabu.glue.core.impl.providers.SystemMethodProvider;
import be.nabu.glue.impl.SimpleExecutionContext;
import be.nabu.glue.impl.SimpleExecutionEnvironment;
import be.nabu.glue.impl.formatters.SimpleOutputFormatter;
import be.nabu.glue.impl.formatters.ValidatingOutputFormatter;
import be.nabu.glue.types.GlueTypeUtils;
import be.nabu.glue.utils.ScriptRuntime;
import be.nabu.glue.utils.ScriptUtils;
import be.nabu.libs.authentication.api.Authenticator;
import be.nabu.libs.authentication.api.Device;
import be.nabu.libs.authentication.api.DeviceValidator;
import be.nabu.libs.authentication.api.PermissionHandler;
import be.nabu.libs.authentication.api.RoleHandler;
import be.nabu.libs.authentication.api.Token;
import be.nabu.libs.authentication.api.TokenValidator;
import be.nabu.libs.authentication.impl.DeviceImpl;
import be.nabu.libs.cache.api.Cache;
import be.nabu.libs.cache.api.CacheEntry;
import be.nabu.libs.cache.api.CacheProvider;
import be.nabu.libs.cache.api.ExplorableCache;
import be.nabu.libs.converter.ConverterFactory;
import be.nabu.libs.converter.api.Converter;
import be.nabu.libs.evaluator.QueryParser;
import be.nabu.libs.evaluator.QueryPart;
import be.nabu.libs.evaluator.QueryPart.Type;
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
import be.nabu.libs.http.glue.api.CacheKeyProvider;
import be.nabu.libs.http.glue.impl.GlueCSSFormatter;
import be.nabu.libs.http.glue.impl.GlueHTTPFormatter;
import be.nabu.libs.http.glue.impl.GlueHTTPUtils;
import be.nabu.libs.http.glue.impl.RequestMethods;
import be.nabu.libs.http.glue.impl.ResponseMethods;
import be.nabu.libs.http.glue.impl.ServerMethods;
import be.nabu.libs.http.glue.impl.SessionMethods;
import be.nabu.libs.http.glue.impl.UserMethods;
import be.nabu.libs.metrics.api.MetricInstance;
import be.nabu.libs.resources.URIUtils;
import be.nabu.libs.types.ComplexContentWrapperFactory;
import be.nabu.libs.types.DefinedTypeResolverFactory;
import be.nabu.libs.types.TypeUtils;
import be.nabu.libs.types.api.ComplexContent;
import be.nabu.libs.types.api.ComplexType;
import be.nabu.libs.types.api.DefinedType;
import be.nabu.libs.types.api.Element;
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
import be.nabu.utils.mime.api.MultiPart;
import be.nabu.utils.mime.impl.FormatException;
import be.nabu.utils.mime.impl.MimeHeader;
import be.nabu.utils.mime.impl.MimeUtils;
import be.nabu.utils.mime.impl.ParsedMimeFormPart;
import be.nabu.utils.mime.impl.PlainMimeContentPart;
import be.nabu.utils.mime.impl.PlainMimeEmptyPart;
import be.nabu.utils.mime.impl.PlainMimePart;

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
	private DeviceValidator deviceValidator;
	private String preferredContentType = MediaType.APPLICATION_JSON;
	private boolean scanBefore = false;
	private String realm = "default";
	private List<ContentRewriter> contentRewriters = new ArrayList<ContentRewriter>();
	private CacheProvider cacheProvider;
	private Converter converter = ConverterFactory.getInstance().getConverter();
	
	private static Logger logger = LoggerFactory.getLogger(GlueListener.class);
	
	private List<CacheKeyProvider> cacheKeyProviders = new ArrayList<CacheKeyProvider>();
	
	private String cookiePath;
	
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
			boolean secure = "true".equals(environment.getParameters().get("secure"));
			URI uri = HTTPUtils.getURI(request, secure);
			String path = URIUtils.normalize(uri.getPath());
			// not sure if we want to keep this but it may trigger odd things as the '/' is replaced with a '.' for script lookup
			if (path.contains(".")) {
				return null;
			}
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
			if (script == null || script.getRoot() == null) {
				return null;
			}
			// the script is matched on single name
			if (requireFullName && !ScriptUtils.getFullName(script).equals(scriptPath)) {
				return null;
			}
			boolean isPublicScript = isPublicScript(script);
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
			
			String deviceId = null;
			boolean isNewDevice = false;
			// check validity of device
			Device device = request.getContent() == null ? null : GlueListener.getDevice(realm, request.getContent().getHeaders());
			if (device == null && deviceValidator != null) {
				device = GlueListener.newDevice(realm, request.getContent().getHeaders());
				deviceId = device.getDeviceId();
				isNewDevice = true;
			}
			
			if (deviceValidator != null && !deviceValidator.isAllowed(token, device)) {
				throw new HTTPException(token == null ? 401 : 403, "User '" + (token == null ? Authenticator.ANONYMOUS : token.getName()) + "' is using an unauthorized device '" + device.getDeviceId() + "' for '" + ScriptUtils.getFullName(script) + "'");
			}
			
			// if we have root annotations, they may contain security annotations
			if (script.getRoot().getContext() != null && script.getRoot().getContext().getAnnotations() != null) {
				if (script.getRoot().getContext().getAnnotations().containsKey("role") && roleHandler != null
						&& !checkRole(roleHandler, token, script.getRoot().getContext().getAnnotations().get("role"))) {
					throw new HTTPException(token == null ? 401 : 403, "User '" + (token == null ? Authenticator.ANONYMOUS : token.getName()) + "' does not have the required role for '" + ScriptUtils.getFullName(script) + "'");
				}
				if (script.getRoot().getContext().getAnnotations().containsKey("permission") && permissionHandler != null
						&& !checkPermission(permissionHandler, token, script.getRoot().getContext().getAnnotations().get("permission"), pathParameters)) {
					throw new HTTPException(token == null ? 401 : 403, "User '" + (token == null ? Authenticator.ANONYMOUS : token.getName()) + "' does not have the required permission for '" + ScriptUtils.getFullName(script) + "'");
				}
			}

			boolean noCsrf = (script.getRoot().getContext() != null && script.getRoot().getContext().getAnnotations() != null && script.getRoot().getContext().getAnnotations().containsKey("nocsrf"));
			String csrfAnnotation = script.getRoot().getContext() != null && script.getRoot().getContext().getAnnotations() != null ? script.getRoot().getContext().getAnnotations().get("csrf") : null;
			if (csrfAnnotation != null) {
				noCsrf = csrfAnnotation.equalsIgnoreCase("none");
			}
			Map<String, Object> input = new HashMap<String, Object>();
			// scan all inputs, check for annotations to indicate what you might want
			@SuppressWarnings("rawtypes")
			Map formParameters = null;
			if (request.getContent() instanceof ParsedMimeFormPart) {
				formParameters = ((ParsedMimeFormPart) request.getContent()).getValues();
				if (formParameters != null && addCsrfCheck && !noCsrf) {
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
					// if you define the token as being single use, remove the token now that it has been used so it can only be used once
					// this is interesting for more sensitive pages like login pages etc
					else if ("single".equals(csrfAnnotation)) {
						session.set(CSRF_TOKEN, null);
					}
				}
			}
			else if (request.getContent() != null && "multipart/form-data".equals(MimeUtils.getContentType(request.getContent().getHeaders()))) {
				formParameters = HTTPUtils.getMultipartFormData(request);
			}
			Map<String, List<String>> queryProperties = URIUtils.getQueryProperties(uri);
			
			// whether or not this script can be cached
			// not all scripts can be cached as they might have conditional execution or permission based logic
			// you need to annotate your scripts to achieve caching
			boolean isCacheable = !refreshScripts && cacheProvider != null && script.getRoot().getContext() != null && script.getRoot().getContext().getAnnotations() != null && script.getRoot().getContext().getAnnotations().containsKey("cache");
			
			List<Header> headersToAdd = scanBefore || isCacheable ? scan(request, queryProperties, formParameters, cookies, input, pathParameters, script.getRoot()) : new ArrayList<Header>();
			
			StringBuilder serializedCacheKey = null;
			String serializedCacheKeyString = null;
			String cacheHash = null;
			Cache cache = isCacheable ? cacheProvider.get(ScriptUtils.getFullName(script)) : null;
			// check the cache for the script
			if (cache != null) {
				serializedCacheKey = new StringBuilder();
				boolean first = true;
				for (String key : input.keySet()) {
					if (first) {
						first = false;
					}
					else {
						serializedCacheKey.append("&");
					}
					serializedCacheKey.append(key).append("=");
					Object object = input.get(key);
					String value;
					if (object == null) {
						value = "null";
					}
					else if (object instanceof String) {
						value = (String) object;
					}
					else {
						value = converter.convert(object, String.class);
						if (value == null) {
							serializedCacheKey = null;
							break;
						}
					}
					serializedCacheKey.append(value.replace("&", "%amp;").replace("=", "%eql;"));
				}
				
				if (serializedCacheKey != null) {
					// check for additional enrichment of the cache key for this page
					for (CacheKeyProvider provider : cacheKeyProviders) {
						String additionalCacheKey = provider.getAdditionalCacheKey(request, token, script);
						if (additionalCacheKey != null) {
							serializedCacheKey.append("&").append(additionalCacheKey.replace("&", "%amp;").replace("=", "%eql;"));
						}
					}
					
					Header lastModifiedHeader = null;
					serializedCacheKeyString = serializedCacheKey.toString();
					cacheHash = hash(serializedCacheKeyString.getBytes(Charset.forName("UTF-8")), "MD5");
					
					boolean isDifferentEtag = false;
					if (request.getContent() != null) {
						Header header = MimeUtils.getHeader("If-None-Match", request.getContent().getHeaders());
						if (header != null && header.getValue() != null) {
							if (!cacheHash.equals(header.getValue())) {
								isDifferentEtag = true;
							}
						}
					}
					// check for non-modified things
					if (cache instanceof ExplorableCache && !isDifferentEtag) {
						CacheEntry entry = ((ExplorableCache) cache).getEntry(serializedCacheKeyString);
						if (entry != null) {
							lastModifiedHeader = new MimeHeader("Last-Modified", HTTPUtils.formatDate(entry.getLastModified()));
							if (request.getContent() != null) {
								Header header = MimeUtils.getHeader("If-Modified-Since", request.getContent().getHeaders());
								if (header != null && header.getValue() != null) {
									Date ifModifiedSince = HTTPUtils.parseDate((String) header.getValue());
									if (!ifModifiedSince.after(entry.getLastModified())) {
										// if it has not been modified, send back a 304
										return new DefaultHTTPResponse(304, HTTPCodes.getMessage(304), new PlainMimeEmptyPart(null, 
											new MimeHeader("Content-Length", "0"), 
											new MimeHeader("Cache-Control", "public"),
											lastModifiedHeader
										));
									}
								}
							}
						}
					}
					
					HTTPResponse response = (HTTPResponse) cache.get(serializedCacheKeyString);
					if (response != null) {
						if (response.getContent() instanceof ContentPart) {
							// we rewrap the content part because we may want to add encoding etc but this would _also_ be used for further decoding (because of how it works)
							response = new DefaultHTTPResponse(response.getCode(), response.getMessage(), new WrappedContentPart((ContentPart) response.getContent()), response.getVersion());
							if (allowEncoding) {
								HTTPUtils.setContentEncoding(response.getContent(), request.getContent().getHeaders());
							}
							if (MimeUtils.getContentLength(response.getContent().getHeaders()) == null && MimeUtils.getHeader("Transfer-Encoding", response.getContent().getHeaders()) == null) {
								response.getContent().setHeader(new MimeHeader("Transfer-Encoding", "chunked"));
							}
						}
						if (response.getContent() != null) {
							// also set it in these responses
							if (lastModifiedHeader != null) {
								response.getContent().setHeader(
									new MimeHeader("Cache-Control", "public"),
									lastModifiedHeader
								);
							}
							// set a cookie for the session if it's a new session
							if (session != null && !session.getId().equals(originalSessionId)) {
								// renew the session as well
								ModifiableHeader cookieHeader = HTTPUtils.newSetCookieHeader(SESSION_COOKIE, session.getId());
								cookieHeader.addComment("Path=" + getCookiePath());
								cookieHeader.addComment("HttpOnly");
								response.getContent().setHeader(cookieHeader);
							}
							if (isNewDevice) {
								ModifiableHeader cookieHeader = HTTPUtils.newSetCookieHeader(
									"Device-" + realm, 
									deviceId,
									new Date(new Date().getTime() + 1000l*60*60*24*365*100),
									getCookiePath(),
									// domain
									null, 
									// secure TODO?
									false,
									// http only
									true
								);
								response.getContent().setHeader(cookieHeader);
							}
							// set etags to identify the cached instance
							response.getContent().setHeader(new MimeHeader("ETag", cacheHash));
						}
						return response;
					}
				}
			}
			
			SimpleExecutionContext executionContext = new SimpleExecutionContext(environment, null, "true".equals(environment.getParameters().get("debug")));
			executionContext.setOutputCurrentLine(false);
			executionContext.setPrincipal(token);
			ScriptRuntime runtime = new ScriptRuntime(script, executionContext, input);
			runtime.addSubstituterProviders(substituterProviders);
			
			// set the context
			runtime.getContext().put(RequestMethods.URL, uri);
			runtime.getContext().put(ServerMethods.ROOT_PATH, serverPath);
			runtime.getContext().put(ServerMethods.COOKIE_PATH, getCookiePath());
			runtime.getContext().put(RequestMethods.ENTITY, request);
			runtime.getContext().put(RequestMethods.GET, queryProperties);
			runtime.getContext().put(RequestMethods.POST, formParameters);
			runtime.getContext().put(RequestMethods.COOKIES, cookies);
			runtime.getContext().put(RequestMethods.PATH, pathParameters);
			runtime.getContext().put(UserMethods.AUTHENTICATOR, getAuthenticator());
			runtime.getContext().put(UserMethods.ROLE_HANDLER, getRoleHandler());
			runtime.getContext().put(UserMethods.PERMISSION_HANDLER, getPermissionHandler());
			runtime.getContext().put(UserMethods.DEVICE_VALIDATOR, getDeviceValidator());
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
			OutputFormatter buffer = scanBefore || isCacheable ? new SimpleOutputFormatter(writer, false, false) : new GlueHTTPFormatter(repository, charset, writer);
			// if we have a @css annotation at the root, set the css formatter
			if (script.getRoot().getContext() != null && script.getRoot().getContext().getAnnotations() != null && script.getRoot().getContext().getAnnotations().containsKey("css")) {
				((SimpleOutputFormatter) buffer).setReplaceVariables(true);
				buffer = new GlueCSSFormatter(buffer);
				headersToAdd.add(new MimeHeader("Content-Type", "text/css"));
			}
			// wrap validation around it
			buffer = new ValidatingOutputFormatter(buffer);
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
			headers.addAll(headersToAdd);
			session = getSession(sessionProvider, runtime); 
			// set a cookie for the session if it's a new session
			if (session != null && !session.getId().equals(originalSessionId)) {
				ModifiableHeader cookieHeader = HTTPUtils.newSetCookieHeader(SESSION_COOKIE, session.getId());
				cookieHeader.addComment("Path=" + getCookiePath());
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
			if (addCsrfCheck && !noCsrf) {
				int formPosition = getFormPosition(stringContent);
				if (formPosition >= 0) {
					// forcibly create a session if csrf checks are required
					// otherwise it is impossible to perform the csrf check on incoming form data
					if (session == null) {
						session = sessionProvider.newSession();
						ModifiableHeader cookieHeader = HTTPUtils.newSetCookieHeader(SESSION_COOKIE, session.getId());
						cookieHeader.addComment("Path=" + getCookiePath());
						cookieHeader.addComment("HttpOnly");
						headers.add(cookieHeader);
						runtime.getContext().put(SessionMethods.SESSION, session);
						
					}
					// remove any previously existing CSRF token
					// only remove it if we have a new form, otherwise getting additional (resourc-y) pages could reset the csrf token of an initial form-containing page
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
			boolean setChunked = false;
			if (contentLength == null) {
				// if there is a stream, we need to go with chunked
				if (stream != null) {
					setChunked = true;
				}
				else {
					headers.add(new MimeHeader("Content-Length", byteContent == null ? "0" : Integer.valueOf(byteContent.length).toString()));
				}
			}
			if (isNewDevice) {
				ModifiableHeader cookieHeader = HTTPUtils.newSetCookieHeader(
					"Device-" + realm, 
					deviceId,
					new Date(new Date().getTime() + 1000l*60*60*24*365*100),
					getCookiePath(),
					// domain
					null, 
					// secure TODO?
					false,
					// http only
					true
				);
				headers.add(cookieHeader);
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
			Integer code = (Integer) runtime.getContext().get(ResponseMethods.RESPONSE_CODE);
			if (code == null) {
				code = 200;
			}
			DefaultHTTPResponse response = new DefaultHTTPResponse(request, code, HTTPCodes.getMessage(code), part);
			
			// check if we want to cache the response
			if (cache != null && serializedCacheKeyString != null) {
				// the response should not contain any set-cookie commands
				Header[] cookieHeaders = MimeUtils.getHeaders("Set-Cookie", response.getContent().getHeaders());
				if (cookieHeaders == null || cookieHeaders.length == 0) {
					cache.put(serializedCacheKeyString, response);
					// if the content for the response was a stream, it will be read by the caching routine, we need to reopen it from cache
					if (stream != null) {
						response = (DefaultHTTPResponse) cache.get(serializedCacheKeyString);
					}
					if (cache instanceof ExplorableCache) {
						CacheEntry entry = ((ExplorableCache) cache).getEntry(serializedCacheKeyString);
						if (entry != null) {
							response.getContent().setHeader(
								new MimeHeader("ETag", cacheHash),
								new MimeHeader("Cache-Control", "public"),
								new MimeHeader("Last-Modified", HTTPUtils.formatDate(entry.getLastModified()))
							);
						}
					}
				}
				else {
					logger.warn("Page {} is skipping cache because response cookies were detected", script);
				}
			}
			if (setChunked) {
				response.getContent().setHeader(new MimeHeader("Transfer-Encoding", "chunked"));
			}
			if (allowEncoding && part instanceof ContentPart) {
				HTTPUtils.setContentEncoding(part, request.getContent().getHeaders());
			}
			return response;
		}
		catch (Exception e) {
			throw new HTTPException(500, e);	
		}
	}

	public static boolean checkPermission(PermissionHandler permissionHandler, Token token, String permissionValue, Map<String, String> pathParameters) throws ParseException {
		QueryParser parser = QueryParser.getInstance();
		boolean allowed = false;
		for (String permission : permissionValue.split("[\\s]*,[\\s]*")) {
			List<QueryPart> parsed = parser.parse(permission);
			if (parsed.isEmpty()) {
				continue;
			}
			String action = (String) parsed.get(0).getContent();
			String context = null;
			// action(variable)
			if (parsed.size() == 4) {
				// TODO: currently limited to path variables because the developer chooses the name, not the user
				// in a future version, I can add support for accessing other variables, for example: action(get: variable)
				// here the developer specifically chooses a variable from another scope
				// but in most cases, the object that you are manipulating should have an identifier in the path anyway...
				if (parsed.get(2).getType() == Type.VARIABLE) {
					context = pathParameters.get(parsed.get(2).getContent());
				}
				// otherwise, we assume it's a string, number,...
				else {
					context = parsed.get(2).getContent() == null ? null : parsed.get(2).getContent().toString();
				}
			}
			// you only have an action
			if (permissionHandler.hasPermission(token, context, action)) {
				allowed = true;
				break;
			}
		}
		return allowed;
	}

	public static boolean checkRole(RoleHandler roleHandler, Token token, String roleValue) {
		boolean allowed = false;
		for (String role : roleValue.split("[\\s]*,[\\s]*")) {
			if (roleHandler.hasRole(token, role)) {
				allowed = true;
				break;
			}
		}
		return allowed;
	}

	public static boolean isPublicScript(Script script) throws IOException, ParseException {
		return (script.getRoot().getContext() != null && script.getRoot().getContext().getAnnotations() != null && script.getRoot().getContext().getAnnotations().containsKey("page"))
				|| script.getRepository() instanceof GroupedScriptRepository && PUBLIC.equals(((GroupedScriptRepository) script.getRepository()).getGroup());
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
		return new PathAnalysis("^" + regex, pathParameters);
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
	
	public static String hash(byte[] bytes, String algorithm) throws IOException {
		try {
			MessageDigest digest = MessageDigest.getInstance(algorithm);
			digest.update(bytes, 0, bytes.length);
			byte [] hash = digest.digest();
			StringBuffer string = new StringBuffer();
			for (int i = 0; i < hash.length; ++i) {
				string.append(Integer.toHexString((hash[i] & 0xFF) | 0x100).substring(1, 3));
			}
			return string.toString();
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
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
	
	public static Device getDevice(String realm, Header...headers) {
		Map<String, List<String>> cookies = HTTPUtils.getCookies(headers);
		List<String> deviceId = cookies.get("Device-" + realm);
		return deviceId == null || deviceId.isEmpty() ? null : new DeviceImpl(deviceId.get(0), GlueHTTPUtils.getUserAgent(headers), GlueHTTPUtils.getHost(headers));
	}
	
	public static Device newDevice(String realm, Header...headers) {
		Map<String, List<String>> cookies = HTTPUtils.getCookies(headers);
		List<String> deviceId = cookies.get("Device-" + realm);
		return new DeviceImpl(deviceId == null || deviceId.isEmpty() ? UUID.randomUUID().toString().replace("-", "") : deviceId.get(0), GlueHTTPUtils.getUserAgent(headers), GlueHTTPUtils.getHost(headers));
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
					value = RequestMethods.url(null); 
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
						try {
							ComplexType type = null;
							try {
								Script script = repository.getScript(optionalType);
								if (script != null) {
									type = GlueTypeUtils.toType(ScriptUtils.getFullName(script), ScriptUtils.getInputs(script), new MapTypeGenerator(), repository);
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
								byte[] bytes = IOUtils.toBytes(readable);
								// if we want a string, use the added context of the charset (if any) to decode it
								if (optionalType.equals("string") || optionalType.equals("java.lang.String")) {
									String originalCharset = MimeUtils.getCharset(entity.getContent().getHeaders());
									value = originalCharset == null ? new String(bytes) : new String(bytes, originalCharset); 
								}
								else {
									OptionalTypeConverter optionalTypeConverter = OptionalTypeProviderFactory.getInstance().getProvider().getConverter(optionalType);
									if (optionalTypeConverter == null) {
										throw new IllegalArgumentException("Can not resolve optional type: " + optionalType);
									}
									value = optionalTypeConverter.convert(bytes);
								}
							}
							else {
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
						}
						finally {
							readable.close();
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
		if (executor.getContext().getAnnotations().containsKey("sanitize")) {
			value = sanitize(value);
		}
		// make sure empty values register as null
		if (value instanceof String && ((String) value).trim().isEmpty()) {
			value = null;
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
	
	public CacheProvider getCacheProvider() {
		return cacheProvider;
	}

	public void setCacheProvider(CacheProvider cacheProvider) {
		this.cacheProvider = cacheProvider;
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
	
	public DeviceValidator getDeviceValidator() {
		return deviceValidator;
	}

	public void setDeviceValidator(DeviceValidator deviceValidator) {
		this.deviceValidator = deviceValidator;
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
	
	public void addCacheKeyProvider(CacheKeyProvider...providers) {
		this.cacheKeyProviders.addAll(Arrays.asList(providers));
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
	
	@SuppressWarnings("unchecked")
	public static Object sanitize(Object value) {
		if (value instanceof String) {
			return sanitizeHTML((String) value);
		}
		else {
			ComplexContent content = value instanceof ComplexContent ? (ComplexContent) value :	ComplexContentWrapperFactory.getInstance().getWrapper().wrap(value);
			if (content != null) {
				for (Element<?> child : TypeUtils.getAllChildren(content.getType())) {
					Object object = content.get(child.getName());
					if (object != null) {
						content.set(child.getName(), sanitize(object));
					}
				}
			}
			return content == null ? value : content;
		}
	}
	
	private static String sanitizeHTML(String value) {
		return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
	}

	public ExecutionEnvironment getEnvironment() {
		return environment;
	}
	
	private static class WrappedContentPart extends PlainMimePart implements ContentPart {

		private ContentPart content;

		public WrappedContentPart(ContentPart content) throws IOException {
			super((MultiPart) content.getParent(), content.getHeaders());
			this.content = content;
		}

		@Override
		public ReadableContainer<ByteBuffer> getReadable() throws IOException {
			return content.getReadable();
		}
		
	}

	public String getCookiePath() {
		return cookiePath == null ? serverPath : cookiePath;
	}

	public void setCookiePath(String cookiePath) {
		this.cookiePath = cookiePath;
	}
	
}
