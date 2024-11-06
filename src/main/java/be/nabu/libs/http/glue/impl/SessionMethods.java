/*
* Copyright (C) 2015 Alexander Verbruggen
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package be.nabu.libs.http.glue.impl;

import be.nabu.glue.utils.ScriptRuntime;
import be.nabu.libs.evaluator.annotations.MethodProviderClass;
import be.nabu.libs.http.api.server.Session;
import be.nabu.libs.http.api.server.SessionProvider;
import be.nabu.libs.http.glue.GlueListener;

@MethodProviderClass(namespace = "session")
public class SessionMethods {
	
	public static final String SESSION_PROVIDER = "sessionProvider";
	public static final String SESSION = "session";
	public static final String SESSION_DESTROYED = "sessionDestroyed";
	
	public static Iterable<String> keys() {
		Session session = getSession();
		return session == null ? null : session;
	}
	
	public static Object get(String key) {
		Session session = getSession();
		return session == null ? null : session.get(key);
	}
	
	public static void set(String key, Object value) {
		Session session = getSession();
		if (session == null) {
			session = create(false);
		}
		if (session != null) {
			session.set(key, value);
		}
	}
	
	public static void destroy() {
		Session session = getSession();
		if (session != null) {
			session.destroy();
		}
		ScriptRuntime.getRuntime().getContext().put(SESSION_DESTROYED, true);
	}
	
	public static boolean exists() {
		return getSession() != null;
	}
	
	public static Session create(Boolean copy) {
		if (copy == null) {
			copy = false;
		}
		Session oldSession = getSession();
		SessionProvider provider = (SessionProvider) ScriptRuntime.getRuntime().getContext().get(SESSION_PROVIDER);
		Session newSession = null;
		if (provider != null) {
			Session session = provider.newSession();
			if (copy && oldSession != null) {
				for (String key : oldSession) {
					session.set(key, oldSession.get(key));
				}
			}
			ScriptRuntime.getRuntime().getContext().put(SESSION, session);
			newSession = session;
		}
		// always destroy the old session if a create is requested
		if (oldSession != null) {
			oldSession.destroy();
		}
		return newSession;
	}
	
	static Session getSession() {
		ScriptRuntime runtime = ScriptRuntime.getRuntime();
		SessionProvider provider = (SessionProvider) runtime.getContext().get(SESSION_PROVIDER);
		return GlueListener.getSession(provider, runtime);
	}
	
	public static boolean hasSessionProvider() {
		return ScriptRuntime.getRuntime().getContext().get(SESSION_PROVIDER) != null;
	}
}
