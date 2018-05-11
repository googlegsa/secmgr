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

package com.google.enterprise.secmgr.ntlmssp;

import javax.annotation.concurrent.Immutable;

/**
 * An enum of the NTLM "negotiate flags".
 *
 * See http://msdn.microsoft.com/en-us/library/cc236621 for details.
 */
@Immutable
public enum NtlmSspFlag {
  NEGOTIATE_UNICODE,
  NEGOTIATE_OEM,
  REQUEST_TARGET,
  RESERVED_9,
  NEGOTIATE_SIGN,
  NEGOTIATE_SEAL,
  NEGOTIATE_DATAGRAM,
  NEGOTIATE_LM_KEY,
  RESERVED_8,
  NEGOTIATE_NTLM,
  NEGOTIATE_NT_ONLY,
  ANONYMOUS,
  NEGOTIATE_OEM_DOMAIN_SUPPLIED,
  NEGOTIATE_OEM_WORKSTATION_SUPPLIED,
  RESERVED_7,
  NEGOTIATE_ALWAYS_SIGN,
  TARGET_TYPE_DOMAIN,
  TARGET_TYPE_SERVER,
  RESERVED_6,
  NEGOTIATE_EXTENDED_SESSION_SECURITY,
  NEGOTIATE_IDENTIFY,
  RESERVED_5,
  REQUEST_NON_NT_SESSION_KEY,
  NEGOTIATE_TARGET_INFO,
  RESERVED_4,
  NEGOTIATE_VERSION,
  RESERVED_3,
  RESERVED_2,
  RESERVED_1,
  NEGOTIATE_128,
  NEGOTIATE_KEY_EXCH,
  NEGOTIATE_56
}
