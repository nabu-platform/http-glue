package be.nabu.libs.http.glue.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.nabu.glue.annotations.GlueMethod;
import be.nabu.glue.utils.ScriptRuntime;
import be.nabu.glue.utils.ScriptUtils;
import be.nabu.libs.evaluator.annotations.MethodProviderClass;
import be.nabu.libs.http.HTTPException;
import be.nabu.libs.metrics.api.MetricInstance;

@MethodProviderClass(namespace = "server")
public class ServerMethods {

	public static final String ROOT_PATH = "rootPath";
	public static final String METRICS = "metrics";
	
	public static MetricInstance metrics() {
		return (MetricInstance) ScriptRuntime.getRuntime().getContext().get(METRICS);
	}
	
	public static String root() {
		String string = (String) ScriptRuntime.getRuntime().getContext().get(ROOT_PATH);
		// make sure there is one trailing slash
		return string == null ? "/" : string.replaceFirst("[/]$", "") + "/";
	}
	
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
	
	@GlueMethod(version = 1)
	public static void abort() {
		ScriptRuntime.getRuntime().abort();
	}
	
	static Logger getLogger() {
		return LoggerFactory.getLogger(ScriptUtils.getFullName(ScriptRuntime.getRuntime().getScript()));
	}
}
