package be.nabu.libs.http.glue.impl;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;

import be.nabu.glue.ScriptRuntime;
import be.nabu.glue.api.AssignmentExecutor;
import be.nabu.glue.api.Executor;
import be.nabu.glue.api.ScriptRepository;
import be.nabu.glue.impl.formatters.SimpleOutputFormatter;
import be.nabu.libs.http.glue.GlueListener;

public class GlueHTTPFormatter extends SimpleOutputFormatter {

	private ScriptRepository repository;
	private Charset charset;

	public GlueHTTPFormatter(ScriptRepository repository, Charset charset, Writer writer) {
		super(writer, false, false);
		this.repository = repository;
		this.charset = charset;
	}

	// inject values if requested by annotations
	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public void before(Executor executor) {
		if (executor instanceof AssignmentExecutor && ((AssignmentExecutor) executor).getVariableName() != null) {
			String name = ((AssignmentExecutor) executor).getVariableName();
			try {
				Object value = GlueListener.getValue(
					repository,
					charset,
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
		String role = annotations.get("role");
		if (role == null || role.trim().isEmpty()) {
			String permission = annotations.get("permission");
			if (permission == null || permission.trim().isEmpty()) {
				return true;
			}
			for (String permissionToCheck : permission.split("[\\s,]+")) {
				if (UserMethods.hasPermission(permissionToCheck, RequestMethods.method().toLowerCase())) {
					return true;
				}
			}
			return false;
		}
		else {
			for (String roleToCheck : role.split("[\\s,]+")) {
				if (UserMethods.hasRole(roleToCheck)) {
					return true;
				}
			}
			return false;
		}
	}
}
