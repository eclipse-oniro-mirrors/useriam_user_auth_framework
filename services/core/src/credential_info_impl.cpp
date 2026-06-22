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

#include "credential_info_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
CredentialInfoImpl::CredentialInfoImpl(int32_t userId, const HdiCredentialInfo &info) : userId_(userId), info_(info)
{
}

uint64_t CredentialInfoImpl::GetCredentialId() const
{
    return info_.credentialId;
}

int32_t CredentialInfoImpl::GetUserId() const
{
    return userId_;
}

uint64_t CredentialInfoImpl::GetExecutorIndex() const
{
    return info_.executorIndex;
}

uint64_t CredentialInfoImpl::GetTemplateId() const
{
    return info_.templateId;
}

AuthType CredentialInfoImpl::GetAuthType() const
{
    return static_cast<AuthType>(info_.authType);
}

uint32_t CredentialInfoImpl::GetExecutorSensorHint() const
{
    return info_.executorSensorHint;
}

uint32_t CredentialInfoImpl::GetExecutorMatcher() const
{
    return info_.executorMatcher;
}

PinSubType CredentialInfoImpl::GetAuthSubType() const
{
    return static_cast<PinSubType>(info_.authSubType);
}

bool CredentialInfoImpl::GetAbandonFlag() const
{
    return info_.isAbandoned;
}

int64_t CredentialInfoImpl::GetValidPeriod() const
{
    return info_.validityPeriod;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS