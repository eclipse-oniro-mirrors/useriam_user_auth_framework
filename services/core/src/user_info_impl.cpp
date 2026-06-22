/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "user_info_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
UserInfoImpl::UserInfoImpl(const int32_t userId, const UserInfo &userInfo) : userId_(userId), userInfo_(userInfo)
{
}

int32_t UserInfoImpl::GetUserId() const
{
    return userId_;
}

uint64_t UserInfoImpl::GetSecUserId() const
{
    return userInfo_.secureUid;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS