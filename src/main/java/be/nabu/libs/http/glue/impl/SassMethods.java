package be.nabu.libs.http.glue.impl;

import be.nabu.libs.evaluator.annotations.MethodProviderClass;
import be.nabu.libs.http.sass.SassCompiler;

@MethodProviderClass(namespace = "sass")
public class SassMethods {
	
	private static SassCompiler compiler = new SassCompiler();
	
	public static String compile(String sass) {
		return compiler.compile2(sass);
	}
}
