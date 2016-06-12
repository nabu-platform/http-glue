package be.nabu.libs.http.glue;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.text.ParseException;

import be.nabu.glue.api.ExecutionContext;
import be.nabu.glue.api.ExecutorGroup;
import be.nabu.glue.api.ScriptRepository;
import be.nabu.glue.impl.parsers.GlueParser;
import be.nabu.libs.evaluator.api.OperationProvider;
import be.nabu.utils.io.IOUtils;

public class GlueCSSParser extends GlueParser {

	public GlueCSSParser(ScriptRepository repository, OperationProvider<ExecutionContext> operationProvider) {
		super(repository, operationProvider);
	}

	@Override
	public ExecutorGroup parse(Reader reader) throws IOException, ParseException {
		StringBuilder builder = new StringBuilder();
		builder.append("@css\n\n");
		int bracketCount = 0;
		String whitespace = "";
		String statementRegex = "^([\\s]*)([\\w-]+[\\s]*:[\\s]*.*)";
		String commentRegex = "^([\\s]*)//(.*)";
		String idRegex = "^([\\s]*)#(.*)";
		String attributeRegex = "^([\\s]*)\\[(.*)";
		String classRegex = "^([\\s]*)\\.(.*)";
		String stateRegex = "^([\\s]*)[:]+(.*)";
		String elementRegex = "^([\\s]*)\\$(.*)";
		String appendRegex = "^([\\s]*)&(.*)";
		for (String line : IOUtils.toString(IOUtils.wrap(reader)).replace("\r", "").split("[\n\r]+")) {
			if (line.contains("}")) {
				bracketCount--;
				whitespace = tabs(bracketCount);
				continue;
			}
			else if (line.trim().isEmpty()) {
				continue;
			}
			boolean isBlock = line.contains("{");
			if (isBlock) {
				line = line.replace("{", "");
			}
			if (line.matches(commentRegex)) {
				if (bracketCount == 0) {
					whitespace = line.replaceFirst(commentRegex, "$1");
				}
				builder.append(whitespace).append(line.replaceFirst(commentRegex, "#$2")).append("\n");
			}
			else if (line.matches(idRegex)) {
				if (bracketCount == 0) {
					whitespace = line.replaceFirst(idRegex, "$1");
				}
				builder.append(whitespace).append(line.replaceFirst(idRegex, "@id $2")).append("\n");
			}
			else if (line.matches(attributeRegex)) {
				if (bracketCount == 0) {
					whitespace = line.replaceFirst(attributeRegex, "$1");
				}
				// the ending bracket is optional
				line = line.replace("]", "");
				builder.append(whitespace).append(line.replaceFirst(attributeRegex, "@attribute $2")).append("\n");
			}
			else if (line.matches(classRegex)) {
				if (bracketCount == 0) {
					whitespace = line.replaceFirst(classRegex, "$1");
				}
				builder.append(whitespace).append(line.replaceFirst(classRegex, "@class $2")).append("\n");
			}
			else if (line.matches(stateRegex)) {
				if (bracketCount == 0) {
					whitespace = line.replaceFirst(stateRegex, "$1");
				}
				builder.append(whitespace).append(line.replaceFirst(stateRegex, "@state $2")).append("\n").append(whitespace).append("@relation self\n");
			}
			else if (line.matches(elementRegex)) {
				if (bracketCount == 0) {
					whitespace = line.replaceFirst(elementRegex, "$1");
				}
				builder.append(whitespace).append(line.replaceFirst(elementRegex, "@element $2")).append("\n");
			}
			else if (line.matches(appendRegex)) {
				if (bracketCount == 0) {
					whitespace = line.replaceFirst(appendRegex, "$1");
				}
				builder.append(whitespace).append(line.replaceFirst(appendRegex, "@append $2")).append("\n");
			}
			else if (line.matches(statementRegex)) {
				if (bracketCount == 0) {
					whitespace = line.replaceFirst(statementRegex, "$1");
				}
				// append whitespace
				builder.append(whitespace);
				// append css syntax
				builder.append("echo(template(\"");
				builder.append(line.replaceFirst(statementRegex, "$2").replace("\"", "\\\""));
				if (!line.endsWith(";")) {
					builder.append(";");
				}
				builder.append("\"))\n");
			}
			else if (!isBlock) {
				if (bracketCount == 0) {
					whitespace = line.replaceFirst("^([\\s]*).*", "$1");
				}
				builder.append(whitespace).append(line.replaceFirst("^[\\s]*", "")).append("\n");
			}
			if (isBlock) {
				builder.append(whitespace).append("sequence\n");
				bracketCount++;
				whitespace = tabs(bracketCount);
			}
		}
		if (bracketCount > 0) {
			throw new ParseException("You have unclosed scopes", 0);
		}
		return super.parse(new StringReader(builder.toString()));
	}
	
	public static String tabs(int amount) {
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < amount; i++) {
			builder.append("\t");
		}
		return builder.toString();
	}

}
