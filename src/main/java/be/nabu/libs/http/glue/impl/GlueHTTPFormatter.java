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

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.Charset;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

import be.nabu.glue.api.AssignmentExecutor;
import be.nabu.glue.api.Executor;
import be.nabu.glue.api.ScriptRepository;
import be.nabu.glue.impl.formatters.SimpleOutputFormatter;
import be.nabu.glue.utils.ScriptRuntime;
import be.nabu.libs.authentication.api.PermissionHandler;
import be.nabu.libs.authentication.api.RoleHandler;
import be.nabu.libs.authentication.api.Token;
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
					RequestMethods.entity(), 
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
	@SuppressWarnings("unchecked")
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
		Token token = UserMethods.token();
		if (role != null && !role.trim().isEmpty()) {
			RoleHandler roleHandler = (RoleHandler) ScriptRuntime.getRuntime().getContext().get(UserMethods.ROLE_HANDLER);
			if (!GlueListener.checkRole(roleHandler, token, role)) {
				return false;
			}
		}
		
		String permission = annotations.get("permission");
		if (permission != null && !permission.trim().isEmpty()) {
			PermissionHandler permissionHandler = (PermissionHandler) ScriptRuntime.getRuntime().getContext().get(UserMethods.PERMISSION_HANDLER);
			try {
				if (!GlueListener.checkPermission(permissionHandler, token, permission, (Map<String, String>) RequestMethods.paths(null))) {
					return false;
				}
			}
			catch (ParseException e) {
				throw new RuntimeException(e);
			}
		}
		return true;
	}
}
