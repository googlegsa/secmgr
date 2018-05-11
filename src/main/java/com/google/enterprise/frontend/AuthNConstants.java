// Copyright 2018 Google Inc.
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

package com.google.enterprise.frontend;


/**
 * This class contains a number of static constants that are related
 * to the AuthN subsystem, but which are broken out into their own class
 * (and their own Google3 library) to facilitate re-use by other components
 *
 *  If the semantics of these constants becomes complex, methods to intpret
 *  them may also be added here.
 *
 *
 */
public class AuthNConstants {

  // ----------
  // session manager key strings - for keys set and used by this class

  // overall session data

  /**
   * what stage is this session in?  see below for possible values and
   * their interpretations
   */
  public static final String AUTHN_SESSION_STAGE_KEY = "AuthN-stage";

  /**
   * time the session was created (in millis since epoch)
   */
  public static final String AUTHN_SESSION_START_TIME_KEY = "AuthN-startTime";

  /**
   * time the session will expire (in millis since epoch)
   * (this is set to the minimum mechanism-specific expiration time,
   *  or [perhaps] to a system-wide max, whichever comes first)
   */
  public static final String AUTHN_SESSION_EXPIRE_TIME_KEY = "AuthN-expireTime";

  /**
   * this contains the "highest-priority" verified user identity from the
   * mechanisms that were run.  This value is passed downstream and
   * is eventually used in the SAML AuthZ SPI, connector AuthZ calls, etc.
   * The AuthN class guarantees that only identities that have been verified
   * against some external source are placed here.
   *
   * "priority" was defined by product management, and is coded by the order
   * in which the AuthN mechanisms are called.
   */
  public static final String AUTHN_SESSION_VERIFIED_IDENTITY_KEY =
    "AuthN-verified-id";

  /**
   * this contains the saml subject, if saml was used.  the saml subject 
   * may be different from the primary verified id
   */
  public static final String AUTHN_SESSION_SAML_SUBJECT_KEY =
    "AuthN-saml-subject";

  public static final String AUTHN_INFO = "AuthN-info";

  public static final String AUTHN_ALL_IDENTITIES =
      "AuthN-allIdentities";

  // AuthN mechanisms specific constants
  //
  // construct SM keys by concatenating the prefix, mechanism, and field
  // e.g.
  // String pswdKey = AUTHN_MECH_PREFIX +
  //   AuthNMechanisms.BASIC_AUTH.toString() + AUTHN_MECH_TOKEN;
  // String basicAuthPassword = sessionManager.get(sessionId, pswdKey);

  public static final String AUTHN_MECH_PREFIX = "AuthN-Mech-";
  public static final String AUTHN_SESSION_ID_COOKIE_NAME = "GSA_SESSION_ID";

  // The app's PVI.
  public static final String GSA_APP_ID = "GSA_APP_ID";

  public static enum AuthNMechanisms {
    BASIC_AUTH,     // aka SekuLite
    FORMS_AUTH,     // was known as (non-SAML) "SSO"
    SAML,           // the SAML SPI
    SSL,            // client-side x.509 certificate authN
    CONNECTORS,     // connector manager authN logic
    SPNEGO_KERBEROS, // GSSAPI/SPNEGO/Kerberos WWW-Authenticate handshake
    SURROGATE        // direct call to security manager /authenticate
  }

  /**
   * this key indicates the status of a particular mechanism.
   * see below for allowed values (e.g. AUTHN_SESSION_STARTING)
   */
  public static final String AUTHN_MECH_STATUS = "_Status";

  /**
   * this is the identity returned by an AuthN mechansim;  it's format depends
   * on the mechanism.  for example, for BASIC_AUTH, this will be the username
   * the user entered.  For SSL, this will be the X.509 DN in the cert.
   */
  public static final String AUTHN_MECH_ID = "_Id";

  /**
   * this boolean value (valid strings are AUTHN_ID_WAS_VALIDATED and
   * AUTHN_ID_WAS_NOT_VALIDATED) indicates whether the AUTHN_MECH_ID was
   * vaidated by the method and can be trusted without futher checking
   */
  public static final String AUTHN_MECH_ID_VERIFIED = "_Id_verified";

  /**
   * this in the time (in millis) that the above AUTHN_MECH_ID_VERIFIED expires
   *
   */
  public static final String AUTHN_MECH_EXPIRES = "_Expires";

  /**
   *
   */
  public static final String AUTHN_MECH_TOKEN = "_Token";

  /**
   * Authentication domain. Its actual meaning depends on the authentication
   * mechanism used to retrieve the identity.
   */
  public static final String AUTHN_MECH_BASIC_AUTH_USER_DOMAIN_KEY =
    AUTHN_MECH_PREFIX + AuthNMechanisms.BASIC_AUTH.toString() + "_USER_DOMAIN";


  // ------------------------------------------
  // string constants that are valid values for the above fields

  // values for AUTHN_MECH_ID_VERIFIED
  public static final String AUTHN_ID_WAS_VALIDATED = "true";
  public static final String AUTHN_ID_WAS_NOT_VALIDATED = "false";

  // special values for AUTHN_SESSION_EXPIRE_TIME_KEY and AUTHN_MECH_EXPIRES
  public static final String NEVER_EXPIRES = "-1";

  /**
   * _STAGE_KEY and _STATUS_KEY value to indicate that EFE should continue
   * to process AuthN.  This is set when a mechanism hasn't been tried yet, or
   * may be set by a mechanism if the process is still going (for example we
   * have issued a challenge redirect but not yet received a response)
   */
  public static final String AUTHN_SESSION_STARTING = "AuthN_underway";

  /**
   * _STAGE_KEY and _STATUS_KEY value to indicate either a particular mechanism
   * or the overall AuthN process is concluded and futher AuthN processing can
   * be skipped (other than checking for expiration times)
   */
  public static final String AUTHN_SESSION_READY = "authenticated";

  /**
   * _STAGE_KEY and _STATUS_KEY value to indicate an authentication method (or overall AuthN)
   * has failed, but we may retry later if required.
   */
  public static final String AUTHN_SESSION_AUTHENTICATION_FAILED = "AuthN_failed";

  /**
   * The following state represents that the user has initated the
   * logout sequence by hitting the "Sign Out" link.
   */
  public static final String AUTHN_SESSION_LOGOUT = "AuthN_logout";

  /**
   * Specifies the URL the user should be redirected to after the
   * AuthN sequence completes.
   */
  public static final String AUTHN_REDIRECT_TO = "AuthN_redirectTo";

  /**
   * Specified if the URL that the user should be redirected to is
   * secure or not. Since this value is stored in a session manager
   * the value it can contain is a string.
   */
  public static final String AUTHN_REDIRECT_IS_SECURE =
      "AuthN_redirectSecure";

  /**
   * Values for AUTHN_REDIRECT_IS_SECURE field.
   */
  public static final String AUTHN_TRUE = "true";
  public static final String AUTHN_FALSE = "false";

  /**
   * The key that holds the URL of Search Home.
   */
  public static final String AUTHN_SEARCH_HOME_URL = "Search_homeUrl";

  /**
   * Specifies the email address of the user associated with the
   * session.
   */
  public static final String AUTHN_USER_EMAIL = "AuthN_email";

  // the constant literal value is also referenced at
  // enterprise/superroot/twiddlers/authz_twiddler.cc
  public static final String AUTHN_SUCCESSFUL = "AuthN_successful";
}
