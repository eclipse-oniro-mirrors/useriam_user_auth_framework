/*
* Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "user_auth_ffi.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_NAPI"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_CALLBACK_CJ

using namespace OHOS::UserIam::UserAuth;

void CjUserAuthCallback::OnAcquireInfo(const int32_t module, const uint32_t acquireInfo, const Attributes &extraInfo)
{
    (void) module;
    (void) acquireInfo;
    (void) extraInfo;
}

void CjUserAuthCallback::OnResult(const int32_t result, const Attributes &extraInfo)
{
    if (this->onResult_ == nullptr) {
        return;
    }

    std::vector<uint8_t> token;
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token);
    int32_t authType{0};
    extraInfo.GetInt32Value(Attributes::ATTR_AUTH_TYPE, authType);

    CjUserAuthResult ret = {
        .result = result,
        .token = token.data(),
        .tokenLen = static_cast<int64_t>(token.size()),
        .authType = static_cast<uint32_t>(authType),
    };

    extraInfo.GetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST, ret.credentialDigest);
    extraInfo.GetUint16Value(Attributes::ATTR_CREDENTIAL_COUNT, ret.credentialCount);
    this->onResult_(ret);
    IAM_LOGI("OnResult: after calling onResult_");
}
