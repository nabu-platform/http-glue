package be.nabu.libs.http.glue.impl;

import java.util.Date;
import java.util.Map;
import java.util.UUID;

import be.nabu.glue.annotations.GlueMethod;
import be.nabu.glue.annotations.GlueParam;
import be.nabu.glue.utils.ScriptRuntime;
import be.nabu.libs.authentication.api.Authenticator;
import be.nabu.libs.authentication.api.Device;
import be.nabu.libs.authentication.api.DeviceValidator;
import be.nabu.libs.authentication.api.PermissionHandler;
import be.nabu.libs.authentication.api.RoleHandler;
import be.nabu.libs.authentication.api.Token;
import be.nabu.libs.authentication.api.TokenValidator;
import be.nabu.libs.authentication.api.TokenWithSecret;
import be.nabu.libs.authentication.api.principals.BasicPrincipal;
import be.nabu.libs.authentication.api.principals.DevicePrincipal;
import be.nabu.libs.authentication.api.principals.SharedSecretPrincipal;
import be.nabu.libs.authentication.impl.DeviceImpl;
import be.nabu.libs.evaluator.annotations.MethodProviderClass;
import be.nabu.libs.http.HTTPException;
import be.nabu.libs.http.core.ServerHeader;
import be.nabu.libs.http.glue.GlueListener;
import be.nabu.libs.metrics.api.MetricInstance;
import be.nabu.utils.mime.api.Header;

@MethodProviderClass(namespace = "user")
public class UserMethods {

	public static final class SharedSecretPrincipalImplementation implements SharedSecretPrincipal, DevicePrincipal {
		private final String secret;
		private final String name;
		private static final long serialVersionUID = 1L;
		private Device device;

		private SharedSecretPrincipalImplementation(String secret, String name, Device device) {
			this.secret = secret;
			this.name = name;
			this.device = device;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public String getSecret() {
			return secret;
		}

		@Override
		public Device getDevice() {
			return device;
		}
		
	}

	public static final class BasicPrincipalImplementation implements BasicPrincipal, DevicePrincipal {
		private final String password;
		private final String name;
		private static final long serialVersionUID = 1L;
		private Device device;

		private BasicPrincipalImplementation(String password, String name, Device device) {
			this.password = password;
			this.name = name;
			this.device = device;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public String getPassword() {
			return password;
		}

		@Override
		public Device getDevice() {
			return device;
		}
	}

	public static final String SSL_ONLY_SECRET = "sslOnlySecret";
	public static final String AUTHENTICATOR = "authenticator";
	public static final String DEVICE_VALIDATOR = "deviceValidator";
	public static final String ROLE_HANDLER = "roleHandler";
	public static final String TOKEN_VALIDATOR = "tokenValidator";
	public static final String PERMISSION_HANDLER = "permissionHandler";
	public static final String TOKEN = "token";
	public static final String REALM = "realm";
	public static final String LOGIN_BLACKLIST = "loginBlacklist";
	public static final String METRICS_LOGIN_FAILED = "loginFailed";
	public static final String METRICS_REMEMBER_FAILED = "rememberFailed";
	public static final String METRICS_USERNAME_FAILED = "usernameFailed";
	
	@SuppressWarnings("unchecked")
	private static boolean isBlacklisted() {
		String ip = GlueHTTPUtils.getIp(RequestMethods.headers(null));
		if (ip != null) {
			Map<String, Date> blacklist = (Map<String, Date>) ScriptRuntime.getRuntime().getContext().get(LOGIN_BLACKLIST);
			if (blacklist != null) {
				Date date = blacklist.get(ip);
				if (date != null && date.before(new Date())) {
					synchronized(blacklist) {
						blacklist.remove(ip);
					}
				}
				else if (date != null) {
					return true;
				}
			}
		}
		return false;
	}
	
	@GlueMethod(description = "Tries to remember the user based on a shared secret")
	public static boolean remember() {
		if (isBlacklisted()) {
			throw new HTTPException(429);
		}
		String realm = realm();
		String cookie = RequestMethods.cookie("Realm-" + realm);
		String deviceId = RequestMethods.cookie("Device-" + realm);
		if (cookie != null && deviceId != null) {
			int index = cookie.indexOf('/');
			if (index > 0) {
				final String name = cookie.substring(0, index);
				final String secret = cookie.substring(index + 1);
				Authenticator authenticator = (Authenticator) ScriptRuntime.getRuntime().getContext().get(AUTHENTICATOR);
				if (authenticator != null) {
					Token token = authenticator.authenticate(realm, new SharedSecretPrincipalImplementation(
						secret, 
						name,
						new DeviceImpl(deviceId, GlueHTTPUtils.getUserAgent(RequestMethods.headers(null)), GlueHTTPUtils.getIp(RequestMethods.headers(null)))
					));
					if (token != null) {
						SessionMethods.create(true);
						SessionMethods.set(GlueListener.buildTokenName(realm), token);
						return true;
					}
					else {
						forget();
						MetricInstance metrics = ServerMethods.metrics();
						if (metrics != null) {
							metrics.increment(METRICS_REMEMBER_FAILED + ":" + GlueHTTPUtils.getIp(RequestMethods.headers(null)), 1);
						}
					}
				}
			}
		}
		return false;
	}
	
	public static boolean forget() {
		String realm = realm();
		String cookie = RequestMethods.cookie("Realm-" + realm);
		// if the remember cookie exists, clear it
		if (cookie != null && !"forgotten".equals(cookie)) {
			ResponseMethods.cookie(
				"Realm-" + realm, 
				"forgotten", 
				// set in the past
				new Date(new Date().getTime() - 1000l*60*60*24),
				// path
				ServerMethods.root(), 
				// domain
				null, 
				// secure
				(Boolean) ScriptRuntime.getRuntime().getContext().get(SSL_ONLY_SECRET),
				// http only
				true
			);
			return true;
		}
		return false;
	}
	
	public static String realm() {
		return (String) ScriptRuntime.getRuntime().getContext().get(REALM);
	}
	
	@GlueMethod(description = "Allows you to retrieve the token for a certain realm")
	public static Token token() {
		return (Token) SessionMethods.get(GlueListener.buildTokenName(realm()));
	}
	
	@GlueMethod(description = "Allows you to check if the current device is allowed for this account")
	public static boolean device() {
		Token token = token();
		String realm = realm();
		DeviceValidator deviceValidator = (DeviceValidator) ScriptRuntime.getRuntime().getContext().get(DEVICE_VALIDATOR);
		if (token != null && deviceValidator != null) {
			// devices are realm specific because you want the id to be globally unique
			// a device may have been approved for use with realm 1 but not realm 2
			// however the id is a primary key and is linked to exactly one user...which is linked to exactly one realm
			String deviceId = RequestMethods.cookie("Device-" + realm);
			boolean isNewDevice = false;
			Header remoteAddress = RequestMethods.header(ServerHeader.REMOTE_ADDRESS.getName());
			if (deviceId == null) {
				Header userAgent = RequestMethods.header("User-Agent");
				deviceId = deviceValidator.newDeviceId(token, remoteAddress == null ? null : remoteAddress.getValue(), userAgent == null ? null : userAgent.getValue());
				isNewDevice = true;
			}
			Boolean allowed = deviceValidator.isAllowed(token, remoteAddress == null ? null : remoteAddress.getValue(), deviceId);
			// the id is unknown
			if (allowed == null) {
				Header userAgent = RequestMethods.header("User-Agent");
				deviceId = deviceValidator.newDeviceId(token, remoteAddress == null ? null : remoteAddress.getValue(), userAgent == null ? null : userAgent.getValue());
				isNewDevice = true;
			}
			allowed = deviceValidator.isAllowed(token, remoteAddress == null ? null : remoteAddress.getValue(), deviceId);
			if (allowed == null) {
				// unset the cookie
				ResponseMethods.cookie(
					"Device-" + realm, 
					"unknown", 
					// Set it to 100 years in the future
					new Date(new Date().getTime() - 1000l*60*60*24),
					// path
					ServerMethods.root(), 
					// domain
					null, 
					// secure
					(Boolean) ScriptRuntime.getRuntime().getContext().get(SSL_ONLY_SECRET),
					// http only
					true
				);
				return false;
			}
			else if (!allowed) {
				return false;
			}
			// set a cookie to recognize device in the future
			if (isNewDevice) {
				ResponseMethods.cookie(
					"Device-" + realm, 
					deviceId, 
					// Set it to 100 years in the future
					new Date(new Date().getTime() + 1000l*60*60*24*365*100),
					// path
					ServerMethods.root(), 
					// domain
					null, 
					// secure
					(Boolean) ScriptRuntime.getRuntime().getContext().get(SSL_ONLY_SECRET),
					// http only
					true
				);
			}
		}
		return true;
	}
	
	@GlueMethod(description = "Authenticates the user with the given password. If succesful, it recreates the session to prevent session spoofing.", returns = "boolean")
	public static boolean authenticate( 
			@GlueParam(name = "name", description = "The user name") final String name, 
			@GlueParam(name = "password", description = "The user password") final String password,
			@GlueParam(name = "remember", description = "Whether or not to remember this login", defaultValue = "true") final Boolean remember) {
		if (isBlacklisted()) {
			throw new HTTPException(429);
		}
		String realm = realm();
		Authenticator authenticator = (Authenticator) ScriptRuntime.getRuntime().getContext().get(AUTHENTICATOR);
		if (authenticator != null) {
			boolean isNewDevice = false;
			String deviceId = RequestMethods.cookie("Device-" + realm);
			if (deviceId == null) {
				deviceId = UUID.randomUUID().toString().replace("-", "");
				isNewDevice = true;
			}
			Token token = authenticator.authenticate(realm, new BasicPrincipalImplementation(
				password, 
				name, 
				new DeviceImpl(deviceId, GlueHTTPUtils.getUserAgent(RequestMethods.headers(null)), GlueHTTPUtils.getIp(RequestMethods.headers(null)))
			));
			// if it's a new device, set a cookie for it
			if (token != null && isNewDevice) {
				ResponseMethods.cookie(
					"Device-" + realm, 
					deviceId, 
					// Set it to 100 years in the future
					new Date(new Date().getTime() + 1000l*60*60*24*365*100),
					// path
					ServerMethods.root(), 
					// domain
					null, 
					// secure
					(Boolean) ScriptRuntime.getRuntime().getContext().get(SSL_ONLY_SECRET),
					// http only
					true
				);
			}
			// if we have generated a token with a secret, set it in a cookie to be remembered
			if (token instanceof TokenWithSecret && ((TokenWithSecret) token).getSecret() != null && (remember == null || remember)) {
				ResponseMethods.cookie(
					"Realm-" + realm, 
					token.getName() + "/" + ((TokenWithSecret) token).getSecret(), 
					// if there is no valid until in the token, set it to a year
					token.getValidUntil() == null ? new Date(new Date().getTime() + 1000l*60*60*24*365) : token.getValidUntil(),
					// path
					ServerMethods.root(), 
					// domain
					null, 
					// secure
					(Boolean) ScriptRuntime.getRuntime().getContext().get(SSL_ONLY_SECRET),
					// http only
					true
				);
			}
			// recreate the session to prevent session spoofing
			if (token != null) {
				SessionMethods.create(true);
				SessionMethods.set(GlueListener.buildTokenName(realm), token);
				return true;
			}
			else {
				MetricInstance metrics = ServerMethods.metrics();
				if (metrics != null) {
					// this allows you to track multiple failed logins from a single ip for a single or multiple user names (non-distributed brute-force attack)
					metrics.increment(METRICS_LOGIN_FAILED + ":" + GlueHTTPUtils.getIp(RequestMethods.headers(null)) + ":" + name, 1);
					// this allows you to tracker multiple failed logins from multiple ips for a single user name (distributed brute-force attack attack)
					metrics.increment(METRICS_USERNAME_FAILED + ":" + name + ":" + GlueHTTPUtils.getIp(RequestMethods.headers(null)), 1);
				}
			}
		}
		return false;
	}
	
	@GlueMethod(description = "Check if the user is authenticated for a given realm", returns = "boolean")
	public static boolean authenticated() {
		String realm = realm();
		Token token = (Token) SessionMethods.get(GlueListener.buildTokenName(realm));
		TokenValidator validator = (TokenValidator) ScriptRuntime.getRuntime().getContext().get(TOKEN_VALIDATOR);
		return token != null && ((validator == null && (token.getValidUntil() == null || token.getValidUntil().after(new Date()))) || validator.isValid(token));
	}
	
	@GlueMethod(description = "Checks if a user has certain roles")
	public static boolean hasRole(@GlueParam(name = "roles", description = "The roles you want to check") String role) {
		String realm = realm();
		Token token = (Token) SessionMethods.get(GlueListener.buildTokenName(realm));
		RoleHandler handler = (RoleHandler) ScriptRuntime.getRuntime().getContext().get(ROLE_HANDLER);
		// the token can be null, in that case the role handler is supposed to check for anonymous access
		return handler != null && handler.hasRole(token, role);
	}
	
	@GlueMethod(description = "Checks if a user has permission to do something")
	public static boolean hasPermission(
		@GlueParam(name = "context", description = "The context where you want to perform the action") String context,
		@GlueParam(name = "action", description = "The action you want to perform on the context") String action) {
		String realm = realm();
		Token token = (Token) SessionMethods.get(GlueListener.buildTokenName(realm));
		PermissionHandler handler = (PermissionHandler) ScriptRuntime.getRuntime().getContext().get(PERMISSION_HANDLER);
		// the token can be null, in that case the role handler is supposed to check for anonymous access
		// note that if no handler is set, the user automatically has permission
		return handler == null || handler.hasPermission(token, context, action);
	}
	
	@GlueMethod(description = "Generates a new salt")
	public static String salt() {
		return UUID.randomUUID().toString().replace("-", "");
	}
}
