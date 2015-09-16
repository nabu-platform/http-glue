package be.nabu.libs.http.glue.impl;

import java.io.IOException;
import java.io.Writer;
import java.util.List;
import java.util.Map;

import be.nabu.glue.ScriptRuntime;
import be.nabu.glue.api.AssignmentExecutor;
import be.nabu.glue.api.Executor;
import be.nabu.glue.impl.formatters.SimpleOutputFormatter;
import be.nabu.libs.http.glue.GlueListener;

public class GlueHTTPFormatter extends SimpleOutputFormatter {

	private GlueListener listener;

	public GlueHTTPFormatter(GlueListener listener, Writer writer) {
		super(writer, false);
		this.listener = listener;
	}

	// inject values if requested by annotations
	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public void before(Executor executor) {
		if (executor instanceof AssignmentExecutor && ((AssignmentExecutor) executor).getVariableName() != null) {
			String name = ((AssignmentExecutor) executor).getVariableName();
			try {
				Object value = listener.getValue(
					RequestMethods.content(), 
					(AssignmentExecutor) executor, 
					SessionMethods.getSession(), 
					(Map<String, List<String>>) RequestMethods.gets(null), 
					(Map) RequestMethods.posts(null), 
					(Map<String, List<String>>) RequestMethods.cookies(null),
					(Map<String, String>) RequestMethods.paths(null)
				);
				if (value != null) {
					ScriptRuntime.getRuntime().getExecutionContext().getPipeline().put(name, value);
				}
			}
			catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
	}

	/**
	 * This checks for the existence of a @realm annotation
	 * Note that the roles in the annotation are OR-ed instead of AND-ed (as the user.hasRoles() does)
	 */
	@Override
	public boolean shouldExecute(Executor executor) {
		if (!super.shouldExecute(executor)) {
			return false;
		}
		Map<String, String> annotations = executor.getContext() != null ? executor.getContext().getAnnotations() : null;
		if (annotations == null) {
			return true;
		}
		String realm = annotations.get("realm");
		String role = annotations.get("role");
		if (role == null || role.trim().isEmpty()) {
			String permission = annotations.get("permission");
			if (permission == null || permission.trim().isEmpty()) {
				return true;
			}
			for (String permissionToCheck : permission.split("[\\s,]+")) {
				if (UserMethods.hasPermission(realm, permissionToCheck, RequestMethods.method().toLowerCase())) {
					return true;
				}
			}
			return false;
		}
		else {
			for (String roleToCheck : role.split("[\\s,]+")) {
				if (UserMethods.hasRoles(realm == null || realm.trim().isEmpty() ? null : realm, roleToCheck)) {
					return true;
				}
			}
			return false;
		}
	}
}
