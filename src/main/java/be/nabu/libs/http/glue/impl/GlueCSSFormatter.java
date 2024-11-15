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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Stack;

import be.nabu.glue.api.AssignmentExecutor;
import be.nabu.glue.api.Executor;
import be.nabu.glue.api.ExecutorGroup;
import be.nabu.glue.api.OutputFormatter;
import be.nabu.glue.api.Script;
import be.nabu.glue.api.runs.GlueValidation;

/**
 * There are a few annotations:
 * 
 * Targeters:
 * - @class: indicates that we are targeting a specific class
 * - @id: indicates that we are targeting a specific id
 * - @element: indicates that we are targeting a specific element
 * - @attribute: allows you to target an attribute, e.g. "@attribute target=_blank" or simply "@attribute target"
 * - @state: allows you to select a state like "active" or "after",...
 * - @select: or the generic "select" which allows you to fill in css
 *
 * Misc:
 * - @relation: allows you to define the relationship to the parent context, by default this is "descendant" (at any level), there is also "child" (>), "adjacent" (+) and "sibling" (~), "self" if you are further specifying something on the element
 * - @append: just appends to the last identifier, whatever that was
 */
public class GlueCSSFormatter implements OutputFormatter {

	private Stack<Executor> context = new Stack<Executor>();
	private boolean contextPrinted, parentPrinted;
	
	private static List<String> singleQuoteStates = Arrays.asList(new String [] { "active", "checked", "disabled", "empty", "enabled", "first-child", "first-of-type", "focus", "hover", 
			"in-range", "invalid", "lang", "last-child", "last-of-type", "link", "not", "nth-child", "nth-last-child", "nth-last-of-type", "nth-of-type", "only-of-type", "only-child", 
			"optional", "out-of-range", "read-only", "read-write", "required", "root", "target", "valid", "visited" });
	
	private static List<String> doubleQuoteStates = Arrays.asList(new String [] { "after", "before", "first-letter", "first-line"  });
	private OutputFormatter parent;
	private boolean autoprefix = true;
	
	private Script root;
	
	public GlueCSSFormatter(OutputFormatter parent) {
		this.parent = parent;
	}

	private boolean hasContext(Map<String, String> annotations) {
		return annotations.get("class") != null 
				|| annotations.get("id") != null 
				|| annotations.get("element") != null
				|| annotations.get("attribute") != null
				|| annotations.get("state") != null
				|| annotations.get("select") != null
				|| annotations.get("append") != null;
	}
	
	@Override
	public void before(Executor executor) {
		if (!(executor instanceof AssignmentExecutor) && executor instanceof ExecutorGroup && executor.getContext() != null && executor.getContext().getAnnotations() != null) {
			Map<String, String> annotations = executor.getContext().getAnnotations();
			if (hasContext(annotations) || annotations.containsKey("media") || annotations.containsKey("keyframes")) {
				if (contextPrinted) {
					print("}", "");
					contextPrinted = false;
				}
				if (annotations.containsKey("media")) {
					if (parentPrinted) {
						parent.print("}\n");
						parentPrinted = false;
					}
					parent.print("@media " + executor.getContext().getAnnotations().get("media").trim() + " {\n");
					parentPrinted = true;
				}
				else if (annotations.containsKey("keyframes")) {
					if (parentPrinted) {
						parent.print("}\n");
						parentPrinted = false;
					}
					parent.print("@keyframes " + executor.getContext().getAnnotations().get("keyframes").trim() + " {\n");
					parentPrinted = true;
				}
				context.push(executor);
			}
		}
		parent.before(executor);
	}
	
	@Override
	public void after(Executor executor) {
		// if we are exiting the current context
		if (!(executor instanceof AssignmentExecutor) && executor instanceof ExecutorGroup && !context.isEmpty() && context.peek().equals(executor)) {
			if (contextPrinted) {
				print("}", "");
				// we have to print the "new" context again
				contextPrinted = false;
			}
			if (parentPrinted && (executor.getContext().getAnnotations().containsKey("media") || executor.getContext().getAnnotations().containsKey("keyframes"))) {
				parent.print("}\n");
				parentPrinted = false;
			}
			context.pop();
		}
		parent.after(executor);
	}
	
	@Override
	public void print(Object...messages) {
		if (messages != null && messages.length > 0) {
			for (Object message : messages) {
				if (message instanceof String && !"}".equals(message)) {
					message = "\t" + message;
				}
				boolean isRaw = message instanceof String && (((String) message).contains("{") || ((String) message).trim().isEmpty());
				if (!contextPrinted && !isRaw) {
					parent.print((parentPrinted ? "\t" : "") + buildContext() + "\n");
					contextPrinted = true;
				}
				parent.print((parentPrinted ? "\t" : "") + message + "\n");
			}
		}
	}
	
	public class CSSContext {
		private String current;
		private String stateModifier;
		public CSSContext() {
			// empty constructor
		}
		public CSSContext(String current, String stateModifier) {
			this.current = current;
			this.stateModifier = stateModifier;
		}
		public String getCurrent() {
			return current;
		}
		public String getStateModifier() {
			return stateModifier;
		}
		public List<CSSContext> push(Executor executor) {
			String current = this.current == null ? "" : this.current;
			String stateModifier = this.stateModifier == null ? null : this.stateModifier;
			List<String> newCurrent = new ArrayList<String>();

			if (executor.getContext().getAnnotations().get("append") != null) {
//				current += executor.getContext().getAnnotations().get("append");
				newCurrent.add(current.replaceAll("([\\s]*,)", ""));
				newCurrent = multiply(newCurrent, "", "", executor.getContext().getAnnotations().get("append").split("[\\s]*,[\\s]*"));
//				current = current.replaceAll("([\\s]*,)", Matcher.quoteReplacement(executor.getContext().getAnnotations().get("append")) + "$1");
			}
			else if (!"self".equals(executor.getContext().getAnnotations().get("relation"))) {
				if (stateModifier != null) {
					current += stateModifier;
					stateModifier = null;
				}
				if (!current.isEmpty()) {
					current += " ";
				}
			}
			
			if (executor.getContext().getAnnotations().get("relation") != null) {
				String relation = executor.getContext().getAnnotations().get("relation").trim();
				// default, don't print
				if (!relation.equals("descendant") && !relation.equals("self") && !relation.isEmpty()) {
					if (relation.equals("child")) {
						relation = ">";
					}
					else if (relation.equals("sibling")) {
						relation = "~";
					}
					else if (relation.equals("adjacent")) {
						relation = "+";
					}
					current += relation + " ";
				}
			}
			if (newCurrent.isEmpty()) {
				newCurrent.add(current);
			}
			
			List<String> newState = new ArrayList<String>();
			if (stateModifier != null) {
				newState.add(stateModifier);
			}
			if (executor.getContext().getAnnotations().get("element") != null) {
				newCurrent = multiply(newCurrent, "", "", executor.getContext().getAnnotations().get("element").trim().split("[\\s]*,[\\s]*"));
			}
			if (executor.getContext().getAnnotations().get("class") != null) {
				newCurrent = multiply(newCurrent, ".", "", executor.getContext().getAnnotations().get("class").trim().split("[\\s]*,[\\s]*"));
			}
			else if (executor.getContext().getAnnotations().get("id") != null) {
				newCurrent = multiply(newCurrent, "#", "", executor.getContext().getAnnotations().get("id").trim().split("[\\s]*,[\\s]*"));
			}
			else if (executor.getContext().getAnnotations().get("attribute") != null) {
				newCurrent = multiply(newCurrent, "[", "]", executor.getContext().getAnnotations().get("attribute").trim().split("[\\s]*,[\\s]*"));
			}
			else if (executor.getContext().getAnnotations().get("state") != null) {
				String [] states = executor.getContext().getAnnotations().get("state").trim().toLowerCase().split("[\\s]*,[\\s]*");
				for (int i = 0; i < states.length; i++) {
					// just in case someone had a leading ":", remove it
					String state = states[i].replaceFirst("^[:]+", "");
					// a state can have functions like lang(en)
					String baseState = state.replaceAll("^([\\w-]+).*", "$1");
					if (singleQuoteStates.contains(baseState)) {
						states[i] = ":" + state;
					}
					else if (doubleQuoteStates.contains(baseState)) {
						states[i] = "::" + state;
					}
					else {
						throw new IllegalArgumentException("Unknown state: " + baseState);
					}
				}
				newState = new ArrayList<String>(Arrays.asList(states));
			}
			if (executor.getContext().getAnnotations().get("select") != null) {
				newCurrent = multiply(newCurrent, "", "", executor.getContext().getAnnotations().get("select").trim());
			}
			List<CSSContext> contexts = new ArrayList<CSSContext>();
			for (String singleCurrent : newCurrent) {
				if (newState.isEmpty()) {
					contexts.add(new CSSContext(singleCurrent, null));
				}
				else {
					for (String singleState : newState) {
						contexts.add(new CSSContext(singleCurrent, singleState));
					}
				}
			}
			return contexts;
		}
		
		private List<String> multiply(List<String> current, String prefix, String postFix, String...newCurrents) {
			List<String> result = new ArrayList<String>();
			if (current.isEmpty()) {
				current.addAll(Arrays.asList(newCurrents));
			}
			else {
				for (String single : current) {
					// the first always has to be autofixed!
					boolean first = true;
					for (String newCurrent : newCurrents) {
						if ((first || autoprefix) && !newCurrent.startsWith(prefix)) {
							newCurrent = prefix + newCurrent;
						}
						if ((first || autoprefix) && !postFix.isEmpty() && !newCurrent.endsWith(postFix)) {
							newCurrent += postFix;
						}
						result.add(single + newCurrent);
						first = false;
					}
				}
			}
			return result;
		}
		
		public String toString() {
			if (current == null && stateModifier == null) {
				return "*";
			}
			else if (current == null) {
				return stateModifier;
			}
			else if (stateModifier == null) {
				return current;
			}
			else {
				return current + stateModifier;
			}
		}
	}

	private String buildContext() {
		CSSContext root = new CSSContext();
		List<CSSContext> contexts = null;
		for (Executor executor : context) {
			if (contexts == null) {
				contexts = root.push(executor);
			}
			else {
				List<CSSContext> newContexts = new ArrayList<CSSContext>();
				for (CSSContext context : contexts) {
					newContexts.addAll(context.push(executor));
				}
				contexts = newContexts;
			}
		}
		StringBuilder builder = new StringBuilder();
		if (contexts == null) {
			builder.append("*");
		}
		else {
			for (CSSContext context : contexts) {
				if (!builder.toString().isEmpty()) {
					builder.append(", ");
				}
				builder.append(context.toString());
			}
		}
		builder.append(" {");
		return builder.toString();
	}
	
	@SuppressWarnings("unused")
	private String buildSingleContext() {
		StringBuilder builder = new StringBuilder();
		boolean first = true;
		for (Executor executor : context) {
			if (first) {
				first = false;
			}
			else if (executor.getContext().getAnnotations().get("append") != null) {
				builder.append(executor.getContext().getAnnotations().get("append").replaceAll("[\\s]+$", ""));
			}
			else if (!"self".equals(executor.getContext().getAnnotations().get("relation"))) {
				builder.append(" ");
			}
			if (executor.getContext().getAnnotations().get("relation") != null) {
				String relation = executor.getContext().getAnnotations().get("relation").trim();
				// default, don't print
				if (!relation.equals("descendant") && !relation.equals("self") && !relation.isEmpty()) {
					if (relation.equals("child")) {
						relation = ">";
					}
					else if (relation.equals("sibling")) {
						relation = "~";
					}
					else if (relation.equals("adjacent")) {
						relation = "+";
					}
					builder.append(relation + " ");
				}
			}
			if (executor.getContext().getAnnotations().get("element") != null) {
				builder.append(executor.getContext().getAnnotations().get("element").trim());
			}
			if (executor.getContext().getAnnotations().get("class") != null) {
				builder.append("." + executor.getContext().getAnnotations().get("class").trim());
			}
			else if (executor.getContext().getAnnotations().get("id") != null) {
				builder.append("#" + executor.getContext().getAnnotations().get("id").trim());
			}
			else if (executor.getContext().getAnnotations().get("attribute") != null) {
				builder.append("[" + executor.getContext().getAnnotations().get("attribute").trim() + "]");
			}
			else if (executor.getContext().getAnnotations().get("state") != null) {
				String state = executor.getContext().getAnnotations().get("state").trim().toLowerCase();
				// a state can have functions like lang(en)
				String baseState = state.replaceAll("^([\\w]+).*", "$1");
				if (singleQuoteStates.contains(baseState)) {
					builder.append(":" + state);
				}
				else if (doubleQuoteStates.contains(baseState)) {
					builder.append("::" + state);
				}
			}
			if (executor.getContext().getAnnotations().get("select") != null) {
				builder.append(executor.getContext().getAnnotations().get("select").trim());
			}
		}
		if (builder.toString().isEmpty()) {
			builder.append("*");
		}
		builder.append(" {");
		return builder.toString();
	}

	@Override
	public void start(Script script) {
		if (root == null) {
			root = script;
		}
		parent.start(script);		
	}

	@Override
	public void validated(GlueValidation...validations) {
		parent.validated(validations);
	}

	@Override
	public void end(Script script, Date started, Date stopped, Exception exception) {
		if (root != null && root.equals(script)) {
			if (contextPrinted) {
				print("}", "");
				// we have to print the "new" context again
				contextPrinted = false;
			}
			if (parentPrinted) {
				parent.print("}\n");
				parentPrinted = false;
			}
		}
		parent.end(script, started, stopped, exception);		
	}

	@Override
	public boolean shouldExecute(Executor executor) {
		return parent.shouldExecute(executor);
	}

	public boolean isAutoprefix() {
		return autoprefix;
	}

	public void setAutoprefix(boolean autoprefix) {
		this.autoprefix = autoprefix;
	}
	
}
