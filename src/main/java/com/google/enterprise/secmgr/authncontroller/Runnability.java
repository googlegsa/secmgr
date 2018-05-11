// Copyright 2010 Google Inc.
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

package com.google.enterprise.secmgr.authncontroller;

import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.CredentialTransform;
import com.google.enterprise.secmgr.config.CredentialTypeName;
import com.google.enterprise.secmgr.config.CredentialTypeSet;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.Verification;

import java.net.URI;
import java.util.List;

import javax.annotation.concurrent.Immutable;
import javax.servlet.http.HttpServletRequest;

/**
 * Modelling of the runnability status of a given mechanism identity.
 */
@Immutable
public final class Runnability {

  /**
   * The result type of a runnability analysis.
   */
  public enum Status { READY, NOT_READY, SATISFIED }

  private final Status status;
  private final ImmutableList<CredentialTransform> transforms;

  private Runnability(Status status, Iterable<CredentialTransform> transforms) {
    this.status = status;
    this.transforms = ImmutableList.copyOf(transforms);
  }

  /**
   * Analyze a given authority's inputs and outputs and decide if it's runnable.
   *
   * @param view The session state to use for the analysis.
   * @param request The http request to use for the analysis.
   * @return Whether this authority's authentication module is ready to run.
   */
  public static Runnability analyzeAuthority(final SessionView view, HttpServletRequest request) {
    AuthnMechanism mech = view.getMechanism();
    Preconditions.checkNotNull(mech);
    List<CredentialTransform> transforms = mech.getCredentialTransforms();

    Status status;
    if (Iterables.all(transforms,
            new Predicate<CredentialTransform>() {
              public boolean apply(CredentialTransform transform) {
                return satisfiesOutputCredentialTypes(view, transform.getOutputs());
              }
            })) {
      status = Status.SATISFIED;
    } else if (Iterables.any(transforms,
            new Predicate<CredentialTransform>() {
              public boolean apply(CredentialTransform transform) {
                return !satisfiesOutputCredentialTypes(view, transform.getOutputs())
                    && satisfiesInputCredentialTypes(view, transform.getInputs());
              }
            })) {
      status = Status.READY;
    } else if (mech.isApplicable(request)) {
      // The mechanism can handle the request based on headers.
      status = Status.READY;
    } else {
      status = Status.NOT_READY;
    }
    return new Runnability(status, transforms);
  }

  /**
   * Analyze the groups module authority's inputs and decide if it's runnable.
   *
   * @param view The session state to use for the analysis.
   * @param request The http request to use for the analysis.
   * @return Whether this authority's authentication module is ready to run.
   */
  public static Runnability.Status analyzeGroupsAuthority(final SessionView view,
      HttpServletRequest request) {
    AuthnMechanism mech = view.getMechanism();
    Preconditions.checkNotNull(mech);
    List<CredentialTransform> transforms = mech.getCredentialTransforms();

    Status status = Status.NOT_READY;
    if (Iterables.any(transforms,
          new Predicate<CredentialTransform>() {
          public boolean apply(CredentialTransform transform) {
                return satisfiesInputCredentialTypes(view, transform.getInputs());
          }
        })) {
      status = Status.READY;
    }
    return status;
  }


  /*
   * Checks if the input credential types for a mechanism are in the given view.
   */
  private static boolean satisfiesInputCredentialTypes(SessionView view,
      CredentialTypeSet credentialTypes) {
    return credentialTypes.getAreVerified()
        ? verificationsHaveTypes(view, view.getVerifications(), credentialTypes.getElements())
        : credentialsHaveTypes(view, view.getCredentials(), credentialTypes.getElements(), false);
  }

  /*
   * Checks if the output credential types for a mechanism are in the view either
   * in gathered credentials or verifications.
   */
  private static boolean satisfiesOutputCredentialTypes(SessionView view,
      CredentialTypeSet credentialTypes) {
    return credentialTypes.getAreVerified()
        ? verificationsHaveTypes(view, getStrictVerifications(view), credentialTypes.getElements())
        : credentialsHaveTypes(view, view.getCredentials(), credentialTypes.getElements(), false);
  }

  /*
   * Get the verifications for a given view's authority.
   */
  private static Iterable<Verification> getStrictVerifications(SessionView view) {
    return view.getSummary()
        .getVerifications(
            Predicates.equalTo(view.getAuthority()),
            view.getTimeStamp());
  }

  private static boolean verificationsHaveTypes(final SessionView view,
      Iterable<Verification> verifications, final Iterable<CredentialTypeName> types) {
    return Iterables.any(verifications,
        new Predicate<Verification>() {
          public boolean apply(Verification verification) {
            return credentialsHaveTypes(view, verification.getCredentials(), types, true);
          }
        });
  }

  private static boolean credentialsHaveTypes(final SessionView view,
      final Iterable<Credential> credentials, Iterable<CredentialTypeName> types,
      final boolean areVerified) {
    return Iterables.all(types,
        new Predicate<CredentialTypeName>() {
          public boolean apply(final CredentialTypeName type) {
            if (type == CredentialTypeName.COOKIES) {
              return !areVerified && haveCookiesToSend(view);
            }
            return Iterables.any(credentials,
                new Predicate<Credential>() {
                  public boolean apply(Credential credential) {
                    return credential.getTypeName() == type
                        && credential.isVerifiable();
                  }
                });
          }
        });
  }

  private static boolean haveCookiesToSend(SessionView view) {
    String sampleUrl = view.getMechanism().getSampleUrl();
    return sampleUrl != null
        && GCookie.haveCookiesToSend(URI.create(sampleUrl),
            view.getUserAgentCookies(),
            view.getAuthorityCookies());
  }

  /**
   * @return The runnability status.
   */
  public Status getStatus() {
    return status;
  }

  /**
   * @return The transforms that the runnability is derived from.
   */
  public List<CredentialTransform> getTransforms() {
    return transforms;
  }
}
