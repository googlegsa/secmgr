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

import com.google.common.base.Preconditions;

import java.io.UnsupportedEncodingException;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

/**
 * An abstraction for the NTLM version info structure.
 *
 * See http://msdn.microsoft.com/en-us/library/cc236621 for details.
 */
@Immutable
public final class NtlmSspVersion extends NtlmBase {
  private static final byte[] RESERVED_3_BYTES = new byte[] { 0, 0, 0 };

  // Windows versions:
  // 5.1 Windows XP SP2
  // 5.0 Windows Server 2003
  // 6.0 Windows Vista, Windows Server 2008, Windows Home Server 2008 V2
  // 6.1 Windows 7, Windows Server 2008 R2
  public static final byte WINDOWS_MAJOR_VERSION_5 = 5;
  public static final byte WINDOWS_MAJOR_VERSION_6 = 6;
  public static final byte WINDOWS_MINOR_VERSION_0 = 0;
  public static final byte WINDOWS_MINOR_VERSION_1 = 1;
  public static final byte WINDOWS_MINOR_VERSION_2 = 2;

  public static final byte NTLMSSP_REVISION_W2K3 = 0x0f;

  private final int major;
  private final int minor;
  private final int build;
  private final int ntlmRevision;

  /**
   * Make an NTLM SSP version object.
   *
   * @param major The operating system's major version.
   * @param minor The operating system's minor version.
   * @param build The operating system's build number.
   * @param ntlmRevision The NTLM revision number.
   */
  public static NtlmSspVersion make(int major, int minor, int build, int ntlmRevision) {
    Preconditions.checkArgument(major >= 0 && major < 0x100);
    Preconditions.checkArgument(minor >= 0 && minor < 0x100);
    Preconditions.checkArgument(build >= 0 && build < 0x10000);
    Preconditions.checkArgument(ntlmRevision >= 0 && ntlmRevision < 0x100);
    return new NtlmSspVersion(major, minor, build, ntlmRevision);
  }

  private NtlmSspVersion(int major, int minor, int build, int ntlmRevision) {
    this.major = major;
    this.minor = minor;
    this.build = build;
    this.ntlmRevision = ntlmRevision;
  }

  public int getMajor() {
    return major;
  }

  public int getMinor() {
    return minor;
  }

  public int getBuild() {
    return build;
  }

  public int getNtlmRevision() {
    return ntlmRevision;
  }

  // The decoder need not be locked since it's always in a single thread.
  static NtlmSspVersion decode(@Nonnull NtlmMessageDecoder decoder)
      throws UnsupportedEncodingException {
    int major = decoder.read8();
    int minor = decoder.read8();
    int build = decoder.read16();
    decoder.skip(3);
    int ntlmRevision = decoder.read8();
    return NtlmSspVersion.make(major, minor, build, ntlmRevision);
  }

  // The encoder need not be locked since it's always in a single thread.
  void encode(@Nonnull NtlmMessageEncoder encoder)
      throws UnsupportedEncodingException {
    encoder.write8(major);
    encoder.write8(minor);
    encoder.write16(build);
    encoder.writeBytes(RESERVED_3_BYTES);
    encoder.write8(ntlmRevision);
  }
}
