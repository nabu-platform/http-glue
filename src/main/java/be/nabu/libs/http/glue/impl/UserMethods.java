package be.nabu.libs.http.glue.impl;

import java.util.Date;
import java.util.UUID;

import be.nabu.glue.ScriptRuntime;
import be.nabu.glue.annotations.GlueMethod;
import be.nabu.glue.annotations.GlueParam;
import be.nabu.libs.authentication.api.Authenticator;
import be.nabu.libs.authentication.api.PermissionHandler;
import be.nabu.libs.authentication.api.RoleHandler;
import be.nabu.libs.authentication.api.Token;
import be.nabu.libs.authentication.api.TokenValidator;
import be.nabu.libs.authentication.api.TokenWithSecret;
import be.nabu.libs.authentication.api.principals.BasicPrincipal;
import be.nabu.libs.authentication.api.principals.SharedSecretPrincipal;
import be.nabu.libs.evaluator.annotations.MethodProviderClass;
import be.nabu.libs.http.glue.GlueListener;

@MethodProviderClass(namespace = "user")
public class UserMethods {

	public static final class SharedSecretPrincipalImplementation implements SharedSecretPrincipal {
		private final String secret;
		private final String name;
		private static final long serialVersionUID = 1L;

		private SharedSecretPrincipalImplementation(String secret, String name) {
			this.secret = secret;
			this.name = name;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public String getSecret() {
			return secret;
		}
	}

	public static final class BasicPrincipalImplementation implements BasicPrincipal {
		private final String password;
		private final String name;
		private static final long serialVersionUID = 1L;

		private BasicPrincipalImplementation(String password, String name) {
			this.password = password;
			this.name = name;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public String getPassword() {
			return password;
		}
	}

	public static final String SSL_ONLY_SECRET = "sslOnlySecret";
	public static final String AUTHENTICATOR = "authenticator";
	public static final String ROLE_HANDLER = "roleHandler";
	public static final String TOKEN_VALIDATOR = "tokenValidator";
	public static final String PERMISSION_HANDLER = "permissionHandler";
	public static final String TOKEN = "token";
	public static final String REALM = "realm";
	
	@GlueMethod(description = "Tries to remember the user based on a shared secret")
	public static boolean remember() {
		String realm = realm();
		String cookie = RequestMethods.cookie("Realm-" + realm);
		if (cookie != null) {
			int index = cookie.indexOf('/');
			if (index > 0) {
				final String name = cookie.substring(0, index);
				final String secret = cookie.substring(index + 1);
				Authenticator authenticator = (Authenticator) ScriptRuntime.getRuntime().getContext().get(AUTHENTICATOR);
				if (authenticator != null) {
					Token token = authenticator.authenticate(realm, new SharedSecretPrincipalImplementation(secret, name));
					if (token != null) {
						SessionMethods.create(true);
						SessionMethods.set(GlueListener.buildTokenName(realm), token);
						return true;
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
	
	@GlueMethod(description = "Authenticates the user with the given password. If succesful, it recreates the session to prevent session spoofing.", returns = "boolean")
	public static boolean authenticate( 
			@GlueParam(name = "name", description = "The user name") final String name, 
			@GlueParam(name = "password", description = "The user password") final String password,
			@GlueParam(name = "remember", description = "Whether or not to remember this login", defaultValue = "true") final Boolean remember) {
		
		String realm = realm();
		Authenticator authenticator = (Authenticator) ScriptRuntime.getRuntime().getContext().get(AUTHENTICATOR);
		if (authenticator != null) {
			Token token = authenticator.authenticate(realm, new BasicPrincipalImplementation(password, name));
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
	public static boolean hasRoles(@GlueParam(name = "roles", description = "The roles you want to check") String...roles) {
		String realm = realm();
		Token token = (Token) SessionMethods.get(GlueListener.buildTokenName(realm));
		RoleHandler handler = (RoleHandler) ScriptRuntime.getRuntime().getContext().get(ROLE_HANDLER);
		// the token can be null, in that case the role handler is supposed to check for anonymous access
		return handler != null && handler.hasRole(token, roles);
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
