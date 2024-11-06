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

package be.nabu.libs.http.glue;

import be.nabu.glue.api.Parser;
import be.nabu.glue.api.ScriptRepository;
import be.nabu.glue.core.api.MethodProvider;
import be.nabu.glue.core.impl.parsers.GlueParserProvider;

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
