/*
 * Copyright (c) 2019 Google LLC.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
#include "util/task/status.h"

#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "glog/logging.h"

using ::std::ostream;
using ::std::string;

namespace util {

namespace {

::grpc::StatusCode ConvertToGRPCErrorCode(int code) {
  switch (code) {
    case ::util::error::OK:
      return ::grpc::OK;
    case ::util::error::CANCELLED:
      return ::grpc::CANCELLED;
    case ::util::error::UNKNOWN:
      return ::grpc::UNKNOWN;
    case ::util::error::INVALID_ARGUMENT:
      return ::grpc::INVALID_ARGUMENT;
    case ::util::error::DEADLINE_EXCEEDED:
      return ::grpc::DEADLINE_EXCEEDED;
    case ::util::error::NOT_FOUND:
      return ::grpc::NOT_FOUND;
    case ::util::error::ALREADY_EXISTS:
      return ::grpc::ALREADY_EXISTS;
    case ::util::error::PERMISSION_DENIED:
      return ::grpc::PERMISSION_DENIED;
    case ::util::error::RESOURCE_EXHAUSTED:
      return ::grpc::RESOURCE_EXHAUSTED;
    case ::util::error::FAILED_PRECONDITION:
      return ::grpc::FAILED_PRECONDITION;
    case ::util::error::ABORTED:
      return ::grpc::ABORTED;
    case ::util::error::OUT_OF_RANGE:
      return ::grpc::OUT_OF_RANGE;
    case ::util::error::UNIMPLEMENTED:
      return ::grpc::UNIMPLEMENTED;
    case ::util::error::INTERNAL:
      return ::grpc::INTERNAL;
    case ::util::error::UNAVAILABLE:
      return ::grpc::UNAVAILABLE;
    case ::util::error::DATA_LOSS:
      return ::grpc::DATA_LOSS;
    default:
      LOG(ERROR) << "Can not convert util::error::Code to grpc::StatusCode";
      return ::grpc::UNKNOWN;
  }
}

const Status& GetOk() {
  static const Status status;
  return status;
}

const Status& GetCancelled() {
  static const Status status(::util::error::CANCELLED, "");
  return status;
}

const Status& GetUnknown() {
  static const Status status(::util::error::UNKNOWN, "");
  return status;
}

}  // namespace

Status::Status() : code_(::util::error::OK), message_("") {}

Status::Status(::util::error::Code error, absl::string_view error_message)
    : code_(error), message_(error_message) {
  if (code_ == ::util::error::OK) {
    message_.clear();
  }
}

Status::Status(const Status& other)
    : code_(other.code_), message_(other.message_) {}

Status& Status::operator=(const Status& other) {
  code_ = other.code_;
  message_ = other.message_;
  return *this;
}

const Status& Status::OK = GetOk();
const Status& Status::CANCELLED = GetCancelled();
const Status& Status::UNKNOWN = GetUnknown();

string Status::ToString() const {
  if (code_ == ::util::error::OK) {
    return "OK";
  }

  return ::absl::Substitute("$0: $1", code_, message_);
}

extern ostream& operator<<(ostream& os, const Status& other) {
  os << other.ToString();
  return os;
}

Status::operator ::grpc::Status() const {
  return ::grpc::Status(ConvertToGRPCErrorCode(code()), this->error_message());
}

}  // namespace util
