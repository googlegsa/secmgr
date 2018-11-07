// Copyright 2008 Google Inc.
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

import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.CREDENTIAL_SEPARATOR_HTML;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.DEFAULT_INTRO_TEXT;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.DEFAULT_PASSWORD_ENTRY_WIDTH;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.DEFAULT_PASSWORD_FIELD_TITLE;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.DEFAULT_USERNAME_ENTRY_WIDTH;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.DEFAULT_USERNAME_FIELD_TITLE;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.FONT_SPECIFICATION;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.FOOTER_HTML;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.HEADER_HTML;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.LOGO_HEIGHT;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.LOGO_URL;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.LOGO_WIDTH;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.ONSUBMIT_FUNCTION_NAME;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.OVERRIDE_FORM_HTML;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.PAGE_TITLE;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.POST_CREDENTIAL_HTML;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.PRE_CREDENTIAL_HTML;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.SUBMIT_BUTTON_JAVASCRIPT;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption.SUBMIT_BUTTON_TEXT;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.PerCredentialOption.INTRO_TEXT;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.PerCredentialOption.PASSWORD_ENTRY_WIDTH;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.PerCredentialOption.PASSWORD_FIELD_TITLE;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.PerCredentialOption.USERNAME_ENTRY_WIDTH;
import static com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.PerCredentialOption.USERNAME_FIELD_TITLE;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import com.google.common.html.HtmlEscapers;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.common.HttpUtil.FormParameterCodingException;
import com.google.enterprise.secmgr.common.SecurePasswordHasher;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.common.Stringify;
import com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.FormGlobalOption;
import com.google.enterprise.secmgr.ulf.UniversalLoginFormCustomization.PerCredentialOption;

import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.annotation.concurrent.NotThreadSafe;
import javax.servlet.http.HttpServletRequest;

/**
 * This class is responsible for generating the HTML for an UniversalLoginform.
 *
 * TODO: This UI generation should probably eventually evolve into
 * using XSLT/XML for the following reasons:
 * - In order to convey the active/inactive status of a credential group in the
 *   case where the user has decided to use the custom HTML override, it is
 *   necessary to insert an extra <style> tag between the <head> tags.  This
 *   is hackish.
 * - If a user uploads custom HTML and then adds a credential group, it will not
 *   be displayed.  If the customer can upload custom XSLT, however, then the
 *   user has the option of writing the XSLT in a manner that would handle
 *   the addition of a credential group.
 *
 */
@NotThreadSafe
public class UniversalLoginFormHtml implements Serializable {
  private static final Logger logger = Logger.getLogger(UniversalLoginFormHtml.class.getName());

  private static final String CUSTOMIZATION_FILE_NAME =
      "../../../../conf/UniversalLoginFormCustomization.conf";

  /**
   * This map is initialized with default values, and then all customizations
   * are inserted into the map.
   */
  private Map<FormGlobalOption, String> options = Maps.newHashMap();

  /**
   * The URL which specifies the action of the form submission (the URL to
   * send the POST to).
   */
  private final String actionUrl;

  /**
   * The externally visible hostname of the GSA (used for the default logo).
   */
  private final String gsaHostname;

  private boolean inputsDisabled;

  private final FileBackedCustomization customization;

  /**
   * Main constructor.
   * @param actionUrl URL to post form to on submission
   * @param gsaHostname The externally visible hostname of the GSA, used for
   *        the default logo image URL.
   */
  public UniversalLoginFormHtml(String actionUrl, String gsaHostname) throws IOException {
    this(actionUrl, gsaHostname,
        new FileBackedCustomization(FileUtil.getContextFile(CUSTOMIZATION_FILE_NAME).toString()));
  }

  /**
   * Used for testing and AdminConsole configuration purposes.
   *
   * TODO: change this to accept a general UniversalLoginFormCustomization instead.
   * This requires fixing martin's TO-DO about readConfig() first.
   */
  public UniversalLoginFormHtml(String actionUrl, String gsaHostname,
      FileBackedCustomization customization) {
    this.actionUrl = actionUrl;
    this.gsaHostname = gsaHostname;
    this.customization = customization;
    inputsDisabled = false;
  }

  public String generateForm(List<FormElement> formElements) throws IOException {
    return generateForm(formElements, null);
  }

  public void setInputsDisabled(boolean disable) {
    inputsDisabled = disable;
  }

  /**
   * Builds an HTML UniversalLoginForm from a given list of FormElements.  The order
   * in which the FormElements is presented corresponds to the order of the
   * input FormElement list.
   */
  public String generateForm(List<FormElement> formElements, String errorMsg) throws IOException {
    loadCustomization();

    if (!options.get(OVERRIDE_FORM_HTML).isEmpty()) {
      return insertStyleString(options.get(OVERRIDE_FORM_HTML),
          styleString(formElements));
    }

    StringBuilder form = new StringBuilder();
    form.append(headerString(actionUrl, formElements));
    form.append(options.get(PRE_CREDENTIAL_HTML));
    String prefix = options.get(PRE_CREDENTIAL_HTML);

    if (errorMsg != null && !errorMsg.isEmpty()) {
      form.append("<p><font color=\"red\">" + errorMsg + "</font></p>");
    }

    for (FormElement element : formElements) {
      form.append(prefix);
      form.append(singleFormArea(element));
      prefix = options.get(CREDENTIAL_SEPARATOR_HTML);
    }

    form.append(options.get(POST_CREDENTIAL_HTML));
    form.append(footerString());
    return form.toString();
  }

  /**
   * Parses a POSTed UniversalLoginForm and updates the given list of FormElements to
   * reflect the input from the POST.  This method assumes that the FormElement
   * list is the same list that was used to generate the form in the POST
   * request.
   *
   * @param request a servlet request that POSTs a user-filled UniversalLoginform
   * @param sessionId The ID of the session this POST is for.
   * @param formElements this must be the same list of FormElements as the one
   *     that was used to generate the page from which the request was posted
   * @return A list of the gathered credentials.
   * @throws FormParameterCodingException if the request body can't be parsed.
   */
  public List<FormResponse> parsePostedForm(HttpServletRequest request, String sessionId,
      List<FormElement> formElements) {
    ImmutableList.Builder<FormResponse> builder = ImmutableList.builder();
    for (FormElement formElem : formElements) {
      if (formElem.isEnabled()) {
        String username = getUniqueParameter(getInputUserName(formElem), request.getParameterMap());
        String password = getUniqueParameter(getInputPassName(formElem), request.getParameterMap());
        logger.info(SessionUtil.logMessage(sessionId,
                "Retrieved user/pass: " + Stringify.object(username)
                + " " + SecurePasswordHasher.getMac(username, password)));
        builder.add(new FormResponse(formElem, username, password));
      }
    }
    return builder.build();
  }

  private static String getUniqueParameter(String key, Map<String, String[]> parameters) {
    String[] values = parameters.get(key);
    if (values.length == 0) {
      return "";
    }
    Preconditions.checkArgument(values.length == 1);
    return values[0];
  }

  /*
   * Generates a form area for a single credential group.  The text displayed
   * and a few other options are customizable via the UniversalLoginFormCustomization
   * interface.
   */
  String singleFormArea(FormElement elem) {
    Map<PerCredentialOption, String> locals =
        customization.getCredentialGroupOptions(elem.getName());
    StringBuilder formContent = new StringBuilder();

    String introText = "Please login to " + elem.getDisplayName() + ":";
    String usernameFieldTitle = options.get(DEFAULT_USERNAME_FIELD_TITLE);
    String passwordFieldTitle = options.get(DEFAULT_PASSWORD_FIELD_TITLE);
    String usernameEntryWidth = options.get(DEFAULT_USERNAME_ENTRY_WIDTH);
    String passwordEntryWidth = options.get(DEFAULT_PASSWORD_ENTRY_WIDTH);

    if (!options.get(DEFAULT_INTRO_TEXT).isEmpty()) {
      introText = options.get(DEFAULT_INTRO_TEXT);
    }
    if (locals.containsKey(INTRO_TEXT)) {
      introText = locals.get(INTRO_TEXT);
    }
    if (locals.containsKey(USERNAME_FIELD_TITLE)) {
      usernameFieldTitle = locals.get(USERNAME_FIELD_TITLE);
    }
    if (locals.containsKey(PASSWORD_FIELD_TITLE)) {
      passwordFieldTitle = locals.get(PASSWORD_FIELD_TITLE);
    }
    if (locals.containsKey(USERNAME_ENTRY_WIDTH)) {
      usernameEntryWidth = locals.get(USERNAME_ENTRY_WIDTH);
    }
    if (locals.containsKey(PASSWORD_ENTRY_WIDTH)) {
      passwordEntryWidth = locals.get(PASSWORD_ENTRY_WIDTH);
    }

    formContent.append("<table style=\"text-align: center;\">\n");
    formContent.append("<tbody>\n");
    formContent.append("<tr>\n");
    formContent.append("<td>\n");

    String inputStatus = elem.isEnabled() ? "" : " disabled";
    String id1 = getActiveId(elem.getName());
    String id2 = getInactiveId(elem.getName());

    formContent.append("<tr id=\"" + id1 + "\">\n");
    formContent.append("<td>\n");
    formContent.append(introText + "\n");
    formContent.append("</td>\n");
    formContent.append("</tr>\n");

    formContent.append("<tr id=\"" + id2 + "\">\n");
    formContent.append("<td>\n");
    formContent.append("<span style=\"color:green\">Logged in to ");
    formContent.append(elem.getDisplayName());
    formContent.append("</span>\n");
    formContent.append("</td>\n");
    formContent.append("</tr>\n");

    formContent.append("<tr>\n");
    formContent.append("<td>\n");
    formContent.append("<table>\n");
    formContent.append("<tbody>\n");

    formContent.append("<tr>\n");
    formContent.append("<td>\n");
    formContent.append("<b>" + usernameFieldTitle + "</b>\n");
    formContent.append("</td>\n");
    formContent.append("<td>\n");
    formContent.append("<input style=\"width: ");
    formContent.append(usernameEntryWidth + ";\" ");
    if (inputsDisabled) {
      formContent.append(" disabled ");
    }
    formContent.append("type=\"text\" name=");
    formContent.append(getInputUserName(elem) + inputStatus + " ");
    String username = elem.getUsername();
    if (username == null) {
      username = "";
    }
    username = HtmlEscapers.htmlEscaper().escape(username);

    formContent.append("value=\"" + username + "\">\n");
    formContent.append("</td>\n");
    formContent.append("</tr>\n");

    formContent.append("<tr>\n");
    formContent.append("<td>\n");
    formContent.append("<b>" + passwordFieldTitle + "</b>\n");
    formContent.append("</td>");
    formContent.append("<td>\n");
    formContent.append("<input style=\"width: ");
    formContent.append(passwordEntryWidth + ";\" ");
    if (inputsDisabled) {
      formContent.append(" disabled ");
    }
    formContent.append("type=\"password\" name=");
    formContent.append(getInputPassName(elem) + inputStatus + ">\n");
    formContent.append("</td>\n");
    formContent.append("</tr>\n");

    formContent.append("</tbody>\n");
    formContent.append("</table>\n");
    formContent.append("</td>\n");
    formContent.append("</tr>\n");
    formContent.append("</tbody>\n");
    formContent.append("</table>\n");
    return formContent.toString();
  }

  /**
   * Generates the customizable HTML that should be placed before the main
   * form code.
   */
  String headerString(String actionUrl, List<FormElement> groups) {
    StringBuilder header = new StringBuilder();
    header.append("<html>\n");
    header.append("<head>\n");
    header.append("<title>" + options.get(PAGE_TITLE) + "</title>\n");
    header.append(styleString(groups));
    header.append(options.get(HEADER_HTML));
    header.append(options.get(SUBMIT_BUTTON_JAVASCRIPT));
    header.append("</head>\n");
    header.append("<body>\n");

    // Display the logo and title.
    header.append("<table cellpadding='0' cellspacing='0' width='100%'>\n");
    header.append(" <tbody>\n");
    header.append(" <tr>\n");
    header.append("  <td>\n");

    // If the custom logo url is empty, remove the img element, since this
    // will confuse the browsers such as Chrome and Safari.
    String url = fixupLogoUrl(options.get(LOGO_URL));
    if (!Strings.isNullOrEmpty(url)) {
      header.append("   <img style='height: ");
      header.append(options.get(LOGO_HEIGHT));
      header.append("; width: ");
      header.append(options.get(LOGO_WIDTH));
      header.append(";' alt='Logo' ");
      header.append("src='");
      header.append(fixupLogoUrl(options.get(LOGO_URL)));
      header.append("'>\n");
    }

    header.append("  </td>\n");
    header.append("  <td style='text-align: right;'>");
    header.append(options.get(PAGE_TITLE));
    header.append("  </td>\n");
    header.append(" </tr>\n");
    header.append("</tbody>\n");
    header.append("</table>\n");
    header.append("<hr style='width: 100%; height: 2px;'>\n");

    // Begin the form.
    header.append("<form method='post' name='universalLogin' action='"
        + actionUrl + "' ");

    // Insert the javascript, if applicable.
    String javascript = options.get(SUBMIT_BUTTON_JAVASCRIPT);
    if (!javascript.isEmpty()) {
      header.append("onsubmit='" + options.get(ONSUBMIT_FUNCTION_NAME) + "'");
    }
    header.append(">\n");
    return header.toString();
  }

  private String fixupLogoUrl(String url) {
    if (url.contains(UniversalLoginFormCustomization.LOCALHOST_MARKER)) {
      // This is a special marker used by the default value of LOGO_URL in
      // UniversalLoginFormCustomization.  That code doesn't know the GSA's
      // correct hostname, so we'll substitute it here.

      if ((gsaHostname == null) || (gsaHostname.isEmpty())) {
        // If the constuctor wasn't given a correct hostname, then return a
        // relative URL, which should point back to the GSA.  This won't work
        // while in the security manager (because the sec-mgr doesn't serve
        // the default image), but will work when constructed by the admin
        // console for the preview mode.
        return url.replace(UniversalLoginFormCustomization.LOCALHOST_MARKER, "");
      }

      return url.replace(UniversalLoginFormCustomization.LOCALHOST_MARKER,
          "http://" + gsaHostname + "/");
    }
    return url;
  }

  /**
   * Returns a string which may be included in the HTML header to
   * guide how the page is displayed.  This style string is included in
   * all forms, including forms where OVERRIDE_FORM_HTML is specified.
   * This enables custom forms to be able to handle cases where a credential
   * group is already authenticated and to display the form accordingly.
   */
  String styleString(List<FormElement> groups) {
    StringBuilder style = new StringBuilder();
    style.append("<style type='text/css'>\n");
    style.append("body\n");
    style.append("{\n");
    style.append("font: " + options.get(FONT_SPECIFICATION) + "\n");
    style.append("}\n");

    style.append("<!--\n");
    for (FormElement elem : groups) {
      String display = elem.isActive() ? "inline" : "none";
      style.append("#" + getActiveId(elem.getName()) +
          " {display:" + display + "; }\n");

      display = elem.isActive() ? "none" : "inline";
      style.append("#" + getInactiveId(elem.getName()) +
          " {display:" + display + "; }\n");
    }
    style.append("-->\n");
    style.append("</style>");
    return style.toString();
  }

  /**
   * Loads the customization configuration from the UniversalLoginFormCustomization.
   * Marked package-private for testing purposes.
   */
  void loadCustomization() throws IOException {
    // TODO: implement a file-change listener in
    // FileBackedCustomization so that it isn't necessary to do this.
    // When this is done, change customization to be of type
    // UniversalLoginFormCustomization.
    customization.readConfig();
    initializeOptions();

    // Override default values with customizations.
    options.putAll(customization.getGlobalOptions());
  }

  private String footerString() {
    StringBuilder builder = new StringBuilder();
    builder.append("<center><input type='submit' value='");
    builder.append(options.get(SUBMIT_BUTTON_TEXT));
    builder.append("'");
    if (inputsDisabled) {
      builder.append(" disabled ");
    }
    builder.append("/></center></form>\n");
    builder.append(options.get(FOOTER_HTML));
    return builder.toString();
  }

  /**
   * Insert the style string in the OVERRIDE_FORM_HTML string so that
   * the form can properly handle credentials that have already been
   * authenticated.
   */
  private String insertStyleString(String html, String style) {
    int index = html.indexOf("<head>");
    if (index == -1) {
      logger.warning("Could not find string '<head>' in custom html. " +
                     "As a result the style string could not be inserted.");
      return html;
    }
    return html.substring(0, index + 6) + style + html.substring(index + 6);
  }

  private String getInputUserName(FormElement element) {
    return "u" + element.getName();
  }

  private String getInputPassName(FormElement element) {
    return "pw" + element.getName();
  }

  /**
   * @param name name of group - cannot have any spaces
   */
  private String getActiveId(String name) {
    return name + "Active";
  }

  /**
   * @param name name of group - cannot have any spaces
   */
  private String getInactiveId(String name) {
    return name + "Inactive";
  }

  private void initializeOptions() {
    options = new HashMap<FormGlobalOption, String>();
    for (FormGlobalOption option : FormGlobalOption.values()) {
      options.put(option, option.getDefaultValue());
    }
  }
}
