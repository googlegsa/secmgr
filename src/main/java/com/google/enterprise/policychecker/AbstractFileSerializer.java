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

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.logging.Logger;

/**
 * Abstract implementation of FileSerializer to provide sane implementations of boilerplate
 * functionality.
 *
 * @param <T> Class to serialize to disk and back.
 *
 */
public abstract class AbstractFileSerializer<T> implements FileSerializer<T> {
  private static final Logger logger = Logger.getLogger(AbstractFileSerializer.class.getName());

  @Override
  public abstract void writeToFile(T t, String filename) throws IOException;

  @Override
  public abstract T parseFromReader(Reader reader) throws IOException;

  @Override
  public T parseFromFile(String filename) throws FileNotFoundException, IOException {
    FileReader fileReader = new FileReader(filename);
    T object = null;

    try {
      object = parseFromReader(new BufferedReader(fileReader));
    } finally {
      fileReader.close();
    }

    return object;
  }

  @Override
  public T parseFromFileAndCatchFileNotFoundException(String filename) throws IOException {
    try {
      return parseFromFile(filename);
    } catch (FileNotFoundException e) {
      logger.warning("Could not parse file: " + e);
      return null;
    }
  }

  /**
   * Convenience method for building a BufferedReader from a Reader if necessary.
   */
  protected BufferedReader makeBufferedReader(Reader reader) {
    BufferedReader br;
    if (reader instanceof BufferedReader) {
      br = (BufferedReader) reader;
    } else {
      br = new BufferedReader(reader);
    }
    return br;
  }
}
