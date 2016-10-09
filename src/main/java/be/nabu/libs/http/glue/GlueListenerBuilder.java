package be.nabu.libs.http.glue;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.Charset;

import be.nabu.glue.Main;
import be.nabu.glue.impl.SimpleExecutionEnvironment;
import be.nabu.glue.utils.MultipleRepository;
import be.nabu.libs.http.api.server.SessionProvider;

public class GlueListenerBuilder {
	public GlueListener build(SessionProvider sessionProvider, Charset charset, String serverPath, String...arguments) throws IOException, URISyntaxException {
		MultipleRepository buildRepository = Main.buildRepository(charset, arguments);
		return new GlueListener(sessionProvider, buildRepository, new SimpleExecutionEnvironment(Main.getEnvironmentName(arguments)), serverPath);
	}
}
