// Copyright 2009 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


package com.google.enterprise.secmgr.ulf;

import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.OVERRIDE_FORM_HTML;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.PAGE_TITLE;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.PerCredentialOption.INTRO_TEXT;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.PerCredentialOption.PASSWORD_FIELD_TITLE;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.PerCredentialOption.USERNAME_FIELD_TITLE;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;

import com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption;
import com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.PerCredentialOption;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Map;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests the basic load/save capabilites of FileBackedCustomization.java.
 */
@RunWith(JUnit4.class)
public class FileBackedCustomizationTest {

  FileBackedCustomization config;

  private static final String GLOBAL_OPTIONS_CLASS_NAME
      = FormGlobalOption.class.getName().substring(
      FormGlobalOption.class.getName().lastIndexOf("$") + 1);

  private static final String PER_CONFIGURATION_CLASS_NAME
      = PerCredentialOption.class.getName().substring(
      PerCredentialOption.class.getName().lastIndexOf("$") + 1);

  private static final String SAMPLE_CONFIG =
      GLOBAL_OPTIONS_CLASS_NAME + "\\:OVERRIDE_FORM_HTML=True\n" +
      GLOBAL_OPTIONS_CLASS_NAME + "\\:PAGE_TITLE=Test\n" +
      PER_CONFIGURATION_CLASS_NAME + "\\:INTRO_TEXT\\:CG1=Intro text 1\n" +
      PER_CONFIGURATION_CLASS_NAME + "\\:INTRO_TEXT\\:CG2=Intro text 2\n" +
      PER_CONFIGURATION_CLASS_NAME + "\\:USERNAME_FIELD_TITLE\\:CG1=User\n" +
      PER_CONFIGURATION_CLASS_NAME + "\\:PASSWORD_FIELD_TITLE\\:CG1=Pass\n" +
      PER_CONFIGURATION_CLASS_NAME + "\\:USERNAME_FIELD_TITLE\\:CG2=Username\n" +
      PER_CONFIGURATION_CLASS_NAME + "\\:PASSWORD_FIELD_TITLE\\:CG2=Password\n" +
      PER_CONFIGURATION_CLASS_NAME + "\\:INTRO_TEXT\\:CG10=Intro\n";


  @Before
  public void setUp() throws Exception {
    config = new FileBackedCustomization();
  }

  @Test
  public void testLoad() {
    byte[] bytes = SAMPLE_CONFIG.getBytes(UTF_8);
    InputStream is = new ByteArrayInputStream(bytes);
    config.readConfig(is);

    // Get global options, test results are correct.
    Map<FormGlobalOption, String> globals = config.getGlobalOptions();
    assertEquals("OVERRIDE_FORM_HTML not correctly loaded", "True",
        globals.get(OVERRIDE_FORM_HTML));
    assertEquals("PAGE_TITLE not correctly loaded", "Test",
        globals.get(PAGE_TITLE));

    // Get credential options, test results are correct.
    Map<PerCredentialOption, String> groupOptions =
        config.getCredentialGroupOptions("CG1");
    assertEquals("INTRO_TEXT not correctly loaded", "Intro text 1",
        groupOptions.get(INTRO_TEXT));
    assertEquals("USERNAME_FIELD_TITLE not correctly loaded", "User",
        groupOptions.get(USERNAME_FIELD_TITLE));
    assertEquals("PASSWORD_FIELD_TITLE not correctly loaded", "Pass",
        groupOptions.get(PASSWORD_FIELD_TITLE));

    groupOptions = config.getCredentialGroupOptions("CG2");
    assertEquals("INTRO_TEXT not correctly loaded", "Intro text 2",
        groupOptions.get(INTRO_TEXT));
    assertEquals("USERNAME_FIELD_TITLE not correctly loaded", "Username",
        groupOptions.get(USERNAME_FIELD_TITLE));
    assertEquals("PASSWORD_FIELD_TITLE not correctly loaded", "Password",
        groupOptions.get(PASSWORD_FIELD_TITLE));

    groupOptions = config.getCredentialGroupOptions("CG10");
    assertEquals("INTRO_TEXT not correctly loaded", "Intro",
        groupOptions.get(INTRO_TEXT));
  }

  /**
   * Saves some data to a file, reads it back in, and checks that the
   * configuration was preserved across the save operation.
   */
  @Test
  public void testSaveAndLoad() {
    ByteArrayOutputStream os = new ByteArrayOutputStream();

    byte[] bytes = SAMPLE_CONFIG.getBytes(UTF_8);
    InputStream is = new ByteArrayInputStream(bytes);
    config.readConfig(is);

    config.saveConfig(os);

    FileBackedCustomization reader = new FileBackedCustomization();

    bytes = os.toByteArray();

    is = new ByteArrayInputStream(bytes);
    reader.readConfig(is);

    assertEquals(config, reader);
  }
}
