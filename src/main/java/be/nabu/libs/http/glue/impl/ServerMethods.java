package be.nabu.libs.http.glue.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.nabu.glue.ScriptRuntime;
import be.nabu.glue.ScriptUtils;
import be.nabu.libs.evaluator.annotations.MethodProviderClass;
import be.nabu.libs.http.HTTPException;

@MethodProviderClass(namespace = "server")
public class ServerMethods {

	public static void fail(String message, Integer code) {
		getLogger().error(message);
		throw new HTTPException(code == null ? 500 : code, message);
	}
	
	public static void info(String message) {
		getLogger().info(message);
	}
	
	public static void debug(String message) {
		getLogger().debug(message);
	}
	
	public static void warn(String message) {
		getLogger().warn(message);
	}
	
	public static void error(String message) {
		getLogger().error(message);
	}
	
	public static void abort() {
		ScriptRuntime.getRuntime().abort();
	}
	
	private static Logger getLogger() {
		return LoggerFactory.getLogger(ScriptUtils.getFullName(ScriptRuntime.getRuntime().getScript()));
	}
}
