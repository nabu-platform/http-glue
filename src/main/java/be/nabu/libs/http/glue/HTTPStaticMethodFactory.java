package be.nabu.libs.http.glue;

import java.util.ArrayList;
import java.util.List;

import be.nabu.glue.api.StaticMethodFactory;
import be.nabu.libs.http.glue.impl.RequestMethods;
import be.nabu.libs.http.glue.impl.ResponseMethods;
import be.nabu.libs.http.glue.impl.ServerMethods;
import be.nabu.libs.http.glue.impl.SessionMethods;
import be.nabu.libs.http.glue.impl.UserMethods;

public class HTTPStaticMethodFactory implements StaticMethodFactory {

	@Override
	public List<Class<?>> getStaticMethodClasses() {
		List<Class<?>> classes = new ArrayList<Class<?>>();
		classes.add(ServerMethods.class);
		classes.add(SessionMethods.class);
		classes.add(UserMethods.class);
		classes.add(ResponseMethods.class);
		classes.add(RequestMethods.class);
		return classes;
	}
	
}
