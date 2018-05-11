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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Reader;

/**
 * Abstraction for a class which can serialize a class to a file and read it back again.
 *
 * @param <T> Class to serialize to disk and back.
 *
 */
public interface FileSerializer<T> {
  public void writeToFile(T t, String filename) throws IOException;
  public T parseFromFile(String filename) throws FileNotFoundException, IOException;
  public T parseFromFileAndCatchFileNotFoundException(String filename) throws IOException;
  public T parseFromReader(Reader reader) throws IOException;
}
