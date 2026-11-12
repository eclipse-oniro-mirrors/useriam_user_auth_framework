/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef USER_ACCESS_CTRL_COMMON_H
#define USER_ACCESS_CTRL_COMMON_H

#include <vector>

#include "napi/native_api.h"
#include "napi/native_common.h"

#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAccessCtrl {
constexpr size_t ARGS_ONE = 1;
constexpr size_t ARGS_TWO = 2;

constexpr size_t PARAM0 = 0;
constexpr size_t PARAM1 = 1;

constexpr const uint64_t MAX_ALLOWABLE_VERIFY_AUTH_TOKEN_DURATION = 24 * 60 * 60 * 1000;

struct AuthToken {
    std::vector<uint8_t> challenge {};
    uint32_t authTrustLevel {0};
    int32_t authType {0};
    int32_t tokenType {0};
    int32_t userId {0};
    uint64_t timeInterval {0};
    uint64_t secureUid {0};
    uint64_t enrolledId {0};
    uint64_t credentialId {0};
};

enum AuthTokenType: int32_t {
    TOKEN_TYPE_LOCAL_AUTH = 0,
    TOKEN_TYPE_LOCAL_RESIGN = 1,
    TOKEN_TYPE_LOCAL_COAUTH = 2,
    TOKEN_TYPE_SCHEDULED_AUTH = 3,
};
} // namespace OHOS
} // namespace UserIam
} // namespace UserAccessCtrl
#endif // USER_ACCESS_CTRL_COMMON_H