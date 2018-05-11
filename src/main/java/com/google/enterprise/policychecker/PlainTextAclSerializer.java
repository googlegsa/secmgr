// Copyright 2012 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.enterprise.policychecker;

import com.google.common.base.Splitter;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

/**
 * Serializes Acl objects to / from Strings using a simple plain-text format.
 *
 */
public class PlainTextAclSerializer implements Serializer<Acl> {

  // Group db so we have consistent references to group objects across ACLs.
  private final Group group;

  public PlainTextAclSerializer() {
    group = null;
  }

  public PlainTextAclSerializer(Group group) {
    this.group = group;
  }

  public String toString(Acl acl) {
    if (acl == null) {
      return null;
    }
    return acl.toString();
  }

  /**
   * Parse an Acl from a line of text. The format of the text is:
   * <p>
   * (((group:)|(user:))?<i>name</i>( right=([^ =])+)?)*
   * <p>
   * In other words: a sequence of names, optionally preceded by the string
   * "user:" or "group:" and optionally followed by space and string right=XXX,
   * where XXX does not contain space or '='. Names are taken to be users or
   * groups according to the prefix. If neither prefix appears,
   * then the name is taken to be a group.  If XXX is "read", the READ right
   * is granted to the preceding principal, otherwise, NONE is granted.  If
   * the right=XXX suffix is omitted altogether, READ is assumed.
   * <p>
   * Examples:
   * <ul>
   * <li>{@code user: adam} adds an Acl consisting of one Ace, one that gives
   * User adam READ-privilege.
   * <li>{@code user: charlie user: david right=none group: eng} adds an Acl with three
   * Aces, giving READ privilege to User "charlie" and to the
   * Group "eng", and denying READ privilege to User "david".
   *
   * @param s the String to parse into an Acl
   * @return a new Acl, parsed from the input String
   */
  public Acl fromString(String s) {
    if (s == null) {
      return null;
    }
    Stack<String> tokens = Utils.splitAclString(s);
    return parseAclFromTokens(tokens);
  }

  /**
   * Legacy method to parse Principal from a series of tokens.  It will ignore leading "user:" or
   * "group:" tokens and only look at the last one.  (The necessity of these semantics is somewhat
   * of an open question but are left because of the legacy nature of the code.)
   */
  protected Principal parsePrincipalFromTokens(Stack<String> tokens) {
    if (tokens.isEmpty()) { return null; }
    String name = tokens.pop();
    boolean isUser = false;
    boolean wasUser = false;
    while (name.equals("group:") || (isUser = name.equals("user:"))) {
      if (tokens.isEmpty()) { return null; }
      name = tokens.pop();
      wasUser = isUser;
    }
    if (group == null) {
      return wasUser ? new User(name) : new Group(name);
    }
    if (wasUser) {
      User user = group.getUser((new User(name)).getAclPrincipal());
      return (user == null) ? new User(name) : user;
    } else {
      Group grp = group.getGroup((new Group(name)).getAclPrincipal());
      return (grp == null) ? new Group(name) : grp;
    }
  }

  /**
   * Parse an Acl from a stack of tokens. This is a helper function for the
   * String overloading of this method; it may be used by other classes that
   * already have a token stack and want to pull off an Acl.
   *
   * @param tokens a Stack of Strings
   * @return an Acl taken from the Stack
   */
  private Acl parseAclFromTokens(Stack<String> tokens) {
    List<Ace> aceList = new ArrayList<Ace>();
    Ace ace = null;
    while ((ace = parseAceFromStack(tokens)) != null) {
      aceList.add(ace);
    }
    return new Acl(aceList);
  }

  private Ace parseAceFromStack(Stack<String> tokens) {
    Principal principal = parsePrincipalFromTokens(tokens);
    if (principal == null) {
      return null;
    }
    // This will canonicalize the reference and add the principal if necessary.
    if (group != null) {
      principal = group.addPrincipal(principal);
    }

    Ace.Right right = Ace.Right.READ;
    String nextToken;
    if (!tokens.isEmpty() && ((nextToken = tokens.peek()) != null)) {
      List<String> rightList = Splitter.on('=').splitToList(nextToken);
      if ((rightList.size() == 2) && ("right".equals(rightList.get(0)))) {
        tokens.pop();
        right = Ace.toRight(rightList.get(1));
      }
    }
    return new Ace(principal, right);
  }
}
