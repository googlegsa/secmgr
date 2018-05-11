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

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Backend interface for universal login form customization.
 *
 * This interface provides concrete enums to list the various customizable
 * options, and specifies default values for those elements.  It also provides an
 * abstract interface for getting and setting options against some unspecified
 * storage backend.  It does not provide an abstraction for an in-memory
 * instance of all the customization data.
 */
public interface UniversalLoginFormCustomization {

  // We do not know the GSA's externally visible hostname at this point
  // in the code.  We'll use "localhost" which we know is wrong, and rely
  // on the UniversalLoginFormHtml to fix-up this URL.
  public static final String LOCALHOST_MARKER = "http://localhost/";
  public static final String DEFAULT_LOGO_URL = LOCALHOST_MARKER + "images/Title_Left.png";

  /**
   * Set of overall options that can be customized by the administrator.
   */
  public enum FormGlobalOption {
    /**
     * If set, overrides all other settings; user must include
     * correctly named form inputs.
     */
    OVERRIDE_FORM_HTML(""),

    PAGE_TITLE("Google Search Appliance Universal Login Form"),
    LOGO_URL(DEFAULT_LOGO_URL),
    LOGO_WIDTH("200"),
    LOGO_HEIGHT("78"),
    HEADER_HTML("<meta content=\"text/html; " +
        "charset=ISO-8859-1\" http-equiv=\"content-type\"/>\n"),
    FOOTER_HTML("</body>\n</html>\n"),
    FONT_SPECIFICATION("medium arial,sans-serif"),
    PRE_CREDENTIAL_HTML("<center>\n<table border=\"0\" cellpadding=\"0\" " +
      "cellspacing=\"0\">\n<tbody>\n<tr>\n<td>\n"),
    CREDENTIAL_SEPARATOR_HTML("</td>\n</tr>\n<tr>\n<td>\n"),
    POST_CREDENTIAL_HTML("</td>\n</tr>\n</tbody>\n</table>\n</center>"),
    SUBMIT_BUTTON_TEXT("Login"),
    SUBMIT_BUTTON_IMAGE(""),
    SUBMIT_BUTTON_JAVASCRIPT(""),
    ONSUBMIT_FUNCTION_NAME(""),

    /**
     * The universal login form will default to generating the intro text based on the
     * credential group name, so no need to specify a static default here.
     */
    DEFAULT_INTRO_TEXT(""),
    DEFAULT_USERNAME_FIELD_TITLE("Username:"),
    DEFAULT_USERNAME_ENTRY_WIDTH("100px"),
    DEFAULT_PASSWORD_FIELD_TITLE("Password:"),
    DEFAULT_PASSWORD_ENTRY_WIDTH("100px");

    private final String defaultValue;

    FormGlobalOption(String value) {
      this.defaultValue = value;
    }

    /**
     * Returns the default value for the option.
     */
    public String getDefaultValue() {
      return defaultValue;
    }
  }

  /**
   * Set of per-credential-group options that can be customized by the
   * administrator.
   */
  public enum PerCredentialOption {
    INTRO_TEXT(""),
    USERNAME_FIELD_TITLE(""),
    USERNAME_ENTRY_WIDTH(""),
    PASSWORD_FIELD_TITLE(""),
    PASSWORD_ENTRY_WIDTH("");

    private final String value;

    PerCredentialOption(String value) {
      this.value = value;
    }

    /**
     * Returns the stored value for the option.
     */
    public String getDefaultValue() {
      return value;
    }
  }

  /**
   * A dumb data object representing a failed validation of an option.
   */
  public class OptionValidationError {
    // TODO: define error codes and/or figure out correct approach
    // for internationalization.
    public FormGlobalOption optionWithError;
  }

  Map<FormGlobalOption, String> getGlobalOptions();

  List<OptionValidationError> setGlobalOptions(Map<FormGlobalOption, String> options);

  Set<String> getCredentialGroups();

  Map<PerCredentialOption, String> getCredentialGroupOptions(String credentialGroupName);

  List<OptionValidationError> setCredentialGroupOptions(String credentialGroupName,
      Map<PerCredentialOption, String> options);
}
