package be.nabu.libs.http.glue;

import be.nabu.glue.api.MethodProvider;
import be.nabu.glue.api.Parser;
import be.nabu.glue.api.ScriptRepository;
import be.nabu.glue.impl.parsers.GlueParserProvider;

public class GlueWebParserProvider extends GlueParserProvider {
	
	public GlueWebParserProvider(MethodProvider... methodProviders) {
		super(methodProviders);
	}

	@Override
	public Parser newParser(ScriptRepository repository, String name) {
		if (name.endsWith(".gcss") && !name.startsWith(".")) {
			// make sure we have the root repository which should have access to all the other repositories
			while (repository.getParent() != null) {
				repository = repository.getParent();
			}
			return new GlueCSSParser(repository, newOperationProvider(repository));
		}
		return super.newParser(repository, name);
	}
	
}
