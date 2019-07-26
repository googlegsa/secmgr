/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.enterprise.secmgr.http;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import junit.framework.TestCase;

/** Tests tracking paths with known authn schemes. */
public final class KnownAuthSchemersTest extends TestCase {

  // conveniently accepts strings instead of URLs
  private static class KAS extends KnownAuthSchemers {
    void addKnown(String url, String scheme) {
      try {
        super.addKnown(new URL(url), scheme);
      } catch (MalformedURLException mue) {
        throw new RuntimeException(mue);
      }
    }
    boolean isKnownBasic(String url) {
      try {
        return super.isKnownBasic(new URL(url));
      } catch (MalformedURLException mue) {
        throw new RuntimeException(mue);
      }
    }
  }

  public void testEmptySaysFalse() { 
    KAS known = new KAS();
    assertFalse(known.isKnownBasic("http://koalabeer.net"));
  }

  public void testHasItself() { 
    KAS known = new KAS();
    known.addKnown("http://whiskytango.com/google/", "Basic");
    assertTrue(known.isKnownBasic("http://whiskytango.com/google/"));
  }

  public void testNonBasic() { 
    KAS known = new KAS();
    known.addKnown("http://whiskytango.com/google/", "NTLM");
    assertFalse(known.isKnownBasic("http://whiskytango.com/google/"));
  }

  public void testSimpleCase() { 
    KAS known = new KAS();
    known.addKnown("http://whiskytango.com/google/", "Basic");
    assertTrue(known.isKnownBasic("http://whiskytango.com/google/doodle"));
  }

  public void testSimpleCase2() { 
    KAS known = new KAS();
    known.addKnown("http://whiskytango.com/google/", "Basic");
    known.addKnown("http://whiskytango.com/google/doo", "Basic");
    assertTrue(known.isKnownBasic("http://whiskytango.com/google/doodle"));
  }

  public void testSimpleCase3() { 
    KAS known = new KAS();
    known.addKnown("http://whiskytango.com/google/", "Basic");
    known.addKnown("http://whiskytango.com/google/doodledorf", "Basic");
    assertTrue(known.isKnownBasic("http://whiskytango.com/google/doodle"));
  }

  public void testBasenameStripped() { 
    KAS known = new KAS();
    known.addKnown("http://whiskytango.com/google/bart", "Basic");
    known.addKnown("http://whiskytango.com/google/fred", "Basic");
    assertTrue(known.isKnownBasic("http://whiskytango.com/google/doodle"));
  }

  public void testMissedBeingKnownByASlash() { 
    KAS known = new KAS();
    known.addKnown("http://whiskytango.com/google/", "Basic");
    assertFalse(known.isKnownBasic("http://whiskytango.com/google"));
  }

  public void testEndsInSlash() { 
    KAS known = new KAS();
    known.addKnown("http://whiskytango.com/google/a/", "Basic");
    assertFalse(known.isKnownBasic("http://whiskytango.com/google"));
    assertTrue(known.isKnownBasic("http://whiskytango.com/google/a/b"));
    assertTrue(known.isKnownBasic("http://whiskytango.com/google/a/b/c"));
    assertTrue(known.isKnownBasic("http://whiskytango.com/google/a/"));
  }

  public void testAddingSubPathIsSkipped() { 
    KAS known = new KAS();
    known.addKnown("http://whiskytango.com/google/a/", "Basic");
    assertFalse(known.isKnownBasic("http://whiskytango.com/google"));
    known.addKnown("http://whiskytango.com/google/a/b", "Basic");
    known.addKnown("http://whiskytango.com/google/a/b/c", "Basic");
    known.addKnown("http://whiskytango.com/google/a/", "Basic");
    Map<String, String> back = known.getBackingMapForTest();
    assertEquals(1, back.size());
    assertTrue("PJO: " + back, back.containsKey("http://whiskytango.com/google/a/"));
    known.addKnown("http://other.net/egret/", "Basic");
    assertFalse(known.isKnownBasic("http://whiskytango.com/google"));
    known.addKnown("http://other.net/egret/apple", "Basic");
    known.addKnown("http://other.net/egret/orange/banana/shoe", "Basic");
    known.addKnown("http://other.net/egret/lite/orangatang", "Basic");
    assertEquals(2, back.size());
    assertTrue(back.containsKey("http://whiskytango.com/google/a/"));
    assertTrue(back.containsKey("http://other.net/egret/"));
  }

  public void testAddingMoreGenericRemovesSubpath() { 
    KAS known = new KAS();
    known.addKnown("http://whiskytango.com/google/a/b", "Basic");
    known.addKnown("http://whiskytango.com/google/a/b/c", "Basic");
    known.addKnown("http://whiskytango.com/google/a/", "Basic");
    Map<String, String> back = known.getBackingMapForTest();
    assertEquals(1, back.size());
    assertTrue(back.containsKey("http://whiskytango.com/google/a/"));
    known.addKnown("http://whiskytango.com/google", "Basic");
    assertEquals(1, back.size());
    assertTrue(back.containsKey("http://whiskytango.com/"));

    known.addKnown("http://shoes.com/1/2/3/4", "Basic");
    known.addKnown("http://shoes.com/1/2/3/5", "Basic");
    known.addKnown("http://shoes.com/1/2/3/6", "Basic");
    assertEquals(2, back.size());
    assertTrue(back.containsKey("http://shoes.com/1/2/3/"));
    assertTrue(back.containsKey("http://whiskytango.com/"));

    known.addKnown("http://shoes.com/1/2", "Basic");
    assertEquals(2, back.size());
    assertTrue(back.containsKey("http://shoes.com/1/"));
    known.addKnown("http://shoes.com/x", "Basic");
    known.addKnown("http://shoes.com/y", "Basic");
    assertEquals(2, back.size());
    assertTrue(back.containsKey("http://shoes.com/"));
    assertTrue(back.containsKey("http://whiskytango.com/"));
  }

  public void testQueryWithSlashesIsFine() {
    KAS known = new KAS();
    known.addKnown("http://wt.com/google/b?query=////a////b///", "Basic");
    assertTrue(known.isKnownBasic("http://wt.com/google/sweet"));
    assertTrue(known.isKnownBasic("http://wt.com/google/marmalade?tonic=yes"));
  }

  public void testFragmentWithSlashesIsFine() {
    KAS known = new KAS();
    known.addKnown("http://wt.com/google/b?q=p#a//b/c/", "Basic");
    assertTrue(known.isKnownBasic("http://wt.com/google/sweet"));
    assertTrue(known.isKnownBasic("http://wt.com/google/marmalade#marduke/l"));
  }

  public void testNoPathNoSlashInKnown() {
    KAS known = new KAS();
    known.addKnown("http://wt.com", "Basic");
    assertTrue(known.isKnownBasic("http://wt.com/mango"));
    assertTrue(known.isKnownBasic("http://wt.com/berry?start#nit"));
  }

  public void testNoPathNoSlashInAsked() {
    KAS known = new KAS();
    known.addKnown("http://wt.com/", "Basic");
    assertTrue(known.isKnownBasic("http://wt.com"));
  }

  public void testPrefixNotEnough() {
    KAS known = new KAS();
    known.addKnown("http://foo.com/google/", "Basic");
    assertFalse(known.isKnownBasic("http://foo.com/google_mtv/"));
  }

  public void testMoreQueryTests() {
    KAS known = new KAS();
    known.addKnown("http://foo.com/google/bar?something=a/b", "Basic");
    assertTrue(known.isKnownBasic("http://foo.com/google/"));
  }

  public void testBareHostPort() {
    KAS known = new KAS();
    known.addKnown("http://foo.com:88", "Basic");
    assertTrue(known.isKnownBasic("http://foo.com:88/bar/"));
  }

}
