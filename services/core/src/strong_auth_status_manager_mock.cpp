/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "strong_auth_status_manager.h"

#include <singleton.h>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class StrongAuthStatusManagerImpl final
    : public StrongAuthStatusManager, public Singleton<StrongAuthStatusManagerImpl> {
public:
    void RegisterStrongAuthListener() override;
    void UnRegisterStrongAuthListener() override;
    void StartSubscribe() override;
    bool IsScreenLockStrongAuth(int32_t userId) override;
    void SyncStrongAuthStatusForAllAccounts() override;
};

void StrongAuthStatusManagerImpl::RegisterStrongAuthListener()
{
}

void StrongAuthStatusManagerImpl::UnRegisterStrongAuthListener()
{
}

void StrongAuthStatusManagerImpl::StartSubscribe()
{
}

bool StrongAuthStatusManagerImpl::IsScreenLockStrongAuth(int32_t userId)
{
    (void)userId;
    return false;
}

void StrongAuthStatusManagerImpl::SyncStrongAuthStatusForAllAccounts()
{
}

StrongAuthStatusManager &StrongAuthStatusManager::Instance()
{
    return StrongAuthStatusManagerImpl::GetInstance();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS