package be.nabu.libs.http.glue;

import java.util.Map;

import be.nabu.libs.http.glue.GlueListener.PathAnalysis;
import junit.framework.TestCase;

public class TestPathAnalysis extends TestCase {
	public void testFullMatch() {
		PathAnalysis analyzed = GlueListener.analyzePath("test/{var1}/something");
		Map<String, String> result = analyzed.analyze("test/haha/something");
		assertNotNull(result);
		assertTrue(!result.isEmpty());
		// too short
		result = analyzed.analyze("test/haha");
		assertTrue(result == null || result.isEmpty());
		// too long
		result = analyzed.analyze("test/haha/something/else");
		assertTrue(result == null || result.isEmpty());
	}
	
	public void testFullMatchWithVariable() {
		PathAnalysis analyzed = GlueListener.analyzePath("test/{var1}/something/{var2}");
		Map<String, String> result = analyzed.analyze("test/haha/something/hehe");
		assertNotNull(result);
		assertTrue(!result.isEmpty());
		// too short
		result = analyzed.analyze("test/haha/something");
		assertTrue(result == null || result.isEmpty());
		// too long
		result = analyzed.analyze("test/haha/something/hehe/test");
		assertTrue(result == null || result.isEmpty());
	}
}
