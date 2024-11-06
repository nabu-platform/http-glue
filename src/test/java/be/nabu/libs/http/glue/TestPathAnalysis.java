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
	
	public void testStartMatch() {
		PathAnalysis analyzed = GlueListener.analyzePath("{var1}/test");
		Map<String, String> result = analyzed.analyze("hehe/test");
		assertEquals(result.get("var1"), "hehe");
	}
	
	public void testEndMatch() {
		PathAnalysis analyzed = GlueListener.analyzePath("hehe/{var1}");
		Map<String, String> result = analyzed.analyze("hehe/test");
		assertEquals(result.get("var1"), "test");
	}
	
	public void testFullMatch2() {
		PathAnalysis analyzed = GlueListener.analyzePath("{var1:.*}");
		Map<String, String> result = analyzed.analyze("hehe/test");
		assertEquals(result.get("var1"), "hehe/test");
	}
}
