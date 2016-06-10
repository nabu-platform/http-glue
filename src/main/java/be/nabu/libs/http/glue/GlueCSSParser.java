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
		String statementRegex = "^([\\s]*)([\\w-]+[\\s]*:[\\s]*.*)";
		String commentRegex = "^([\\s]*)//(.*)";
		String idRegex = "^([\\s]*)#(.*)";
		String classRegex = "^([\\s]*)\\.(.*)";
		String stateRegex = "^([\\s]*)[:]+(.*)";
		String elementRegex = "^([\\s]*)\\$(.*)";
		String appendRegex = "^([\\s]*)&(.*)";
		for (String line : IOUtils.toString(IOUtils.wrap(reader)).replace("\r", "").split("[\n\r]+")) {
			if (line.contains("}")) {
				continue;
			}
			boolean isBlock = line.contains("{");
			if (isBlock) {
				line = line.replace("{", "");
			}
			if (line.matches(commentRegex)) {
				builder.append(line.replaceFirst(commentRegex, "$1#$2")).append("\n");
			}
			else if (line.matches(idRegex)) {
				builder.append(line.replaceFirst(idRegex, "$1@id $2")).append("\n");
			}
			else if (line.matches(classRegex)) {
				builder.append(line.replaceFirst(classRegex, "$1@class $2")).append("\n");
			}
			else if (line.matches(stateRegex)) {
				builder.append(line.replaceFirst(stateRegex, "$1@state $2")).append("\n").append(line.replaceFirst(stateRegex, "$1")).append("@relation self\n");
			}
			else if (line.matches(elementRegex)) {
				builder.append(line.replaceFirst(elementRegex, "$1@element $2")).append("\n");
			}
			else if (line.matches(appendRegex)) {
				builder.append(line.replaceFirst(appendRegex, "$1@append $2")).append("\n");
			}
			else if (line.matches(statementRegex)) {
				// append original whitespace
				builder.append(line.replaceFirst(statementRegex, "$1"));
				// append css syntax
				builder.append("echo(template(\"");
				builder.append(line.replaceFirst(statementRegex, "$2").replace("\"", "\\\""));
				if (!line.endsWith(";")) {
					builder.append(";");
				}
				builder.append("\"))\n");
			}
			else if (!isBlock) {
				builder.append(line).append("\n");
			}
			if (isBlock) {
				builder.append(line.replaceFirst("^([\\s]*).*", "$1")).append("sequence\n");
			}
		}
		return super.parse(new StringReader(builder.toString()));
	}

}
