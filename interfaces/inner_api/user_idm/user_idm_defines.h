/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef USER_IDM_DEFINES_H
#define USER_IDM_DEFINES_H

#include <vector>
#include <cstdint>
#include "common_info.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
struct CredentialInfo {
    uint64_t credentialId;
    AuthType authType;
    AuthSubType authSubType;
    uint64_t templateId;
};

struct EnrolledInfo {
    AuthType authType;
    uint64_t enrolledId;
};

struct SecInfo {
    uint64_t secureUid;
    uint32_t enrolledInfoLen;
    std::vector<EnrolledInfo> enrolledInfo;
};

struct AddCredInfo {
    AuthType authType;
    AuthSubType authSubType;
    std::vector<uint8_t> token;
};

struct  RequestResult {
    uint64_t credentialId;
    std::vector<uint8_t> rootSecret;
};
}  // namespace UserAuth
}  // namespace UserIAM
}  // namespace OHOS
namespace OHOS {
namespace UserIAM {
namespace UserAuth {
using CredentialInfo = OHOS::UserIam::UserAuth::CredentialInfo;
using EnrolledInfo = OHOS::UserIam::UserAuth::EnrolledInfo;
using SecInfo = OHOS::UserIam::UserAuth::SecInfo;
using AddCredInfo = OHOS::UserIam::UserAuth::AddCredInfo;
using RequestResult = OHOS::UserIam::UserAuth::RequestResult;
}
}
}
namespace OHOS {
namespace UserIAM {
namespace UserIDM {
using CredentialInfo = OHOS::UserIam::UserAuth::CredentialInfo;
using EnrolledInfo = OHOS::UserIam::UserAuth::EnrolledInfo;
using SecInfo = OHOS::UserIam::UserAuth::SecInfo;
using AddCredInfo = OHOS::UserIam::UserAuth::AddCredInfo;
using RequestResult = OHOS::UserIam::UserAuth::RequestResult;
}
}
}
#endif // USER_IDM_DEFINES_H