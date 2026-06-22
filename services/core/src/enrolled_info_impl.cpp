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

#include "enrolled_info_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
EnrolledInfoImpl::EnrolledInfoImpl(int32_t userId, const HdiEnrolledInfo &info) : userId_(userId), info_(info)
{
}

int32_t EnrolledInfoImpl::GetUserId() const
{
    return userId_;
}

AuthType EnrolledInfoImpl::GetAuthType() const
{
    return static_cast<AuthType>(info_.authType);
}

uint64_t EnrolledInfoImpl::GetEnrolledId() const
{
    return info_.enrolledId;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS