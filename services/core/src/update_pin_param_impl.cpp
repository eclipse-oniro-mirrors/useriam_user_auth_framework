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

#include "update_pin_param_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
UpdatePinParamImpl::UpdatePinParamImpl(uint64_t oldCredentialId, const std::vector<uint8_t> &oldRootSecret,
    const std::vector<uint8_t> &rootSecret, const std::vector<uint8_t> &authToken)
    : oldCredentialId_(oldCredentialId), oldRootSecret_(oldRootSecret), rootSecret_(rootSecret), authToken_(authToken)
{
}

uint64_t UpdatePinParamImpl::GetOldCredentialId() const
{
    return oldCredentialId_;
}

std::vector<uint8_t> UpdatePinParamImpl::GetOldRootSecret() const
{
    return oldRootSecret_;
}

std::vector<uint8_t> UpdatePinParamImpl::GetRootSecret() const
{
    return rootSecret_;
}

std::vector<uint8_t> UpdatePinParamImpl::GetAuthToken() const
{
    return authToken_;
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS