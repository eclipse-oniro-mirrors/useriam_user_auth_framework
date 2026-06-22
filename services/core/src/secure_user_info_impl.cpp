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

#include "secure_user_info_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
SecureUserInfoImpl::SecureUserInfoImpl(int32_t userId, uint64_t secUserId,
    std::vector<std::shared_ptr<EnrolledInfoInterface>> &enrolledInfos)
    : userId_(userId), secUserId_(secUserId), enrolledInfos_(enrolledInfos)
{
}

int32_t SecureUserInfoImpl::GetUserId() const
{
    return userId_;
}

uint64_t SecureUserInfoImpl::GetSecUserId() const
{
    return secUserId_;
}

std::vector<std::shared_ptr<EnrolledInfoInterface>> SecureUserInfoImpl::GetEnrolledInfo() const
{
    return enrolledInfos_;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS