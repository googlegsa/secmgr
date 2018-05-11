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
package com.google.enterprise.secmgr.authncontroller;

import java.lang.reflect.InvocationTargetException;

/**
 * Create recordio based serializer if it exists in the classpath, json based otherwise.
 */
public class AclPrincipalStoreFactory {

  private static Class<?> clazz;

  static {
    try {
      clazz = Class.forName("com.google.enterprise.secmgr.authncontroller.AclPrincipalStoreRecordIOBased");
    } catch (ClassNotFoundException e) {
      try {
        clazz =
            Class.forName("com.google.enterprise.secmgr.authncontroller.AclPrincipalStoreRecordJsonBased");
      } catch (ClassNotFoundException exc) {
        throw new RuntimeException(exc);
      }
    }
  }

  @SuppressWarnings("unchecked")
  public static AclPrincipalStore create() {
    try {
      return (AclPrincipalStore) clazz.getConstructor().newInstance();
    } catch (NoSuchMethodException | SecurityException | InstantiationException
        | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
      throw new RuntimeException(e);
    }
  }

  private AclPrincipalStoreFactory() {
  }
}
