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

#include "os_accounts_manager.h"

#include <singleton.h>

#include "system_ability_listener.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class OsAccountsManagerImpl final : public OsAccountsManager, public Singleton<OsAccountsManagerImpl> {
public:
    void StartSubscribe() override;
    void OnOsAccountSaAdd() override;
    void OnOsAccountSaRemove() override;
};

void OsAccountsManagerImpl::StartSubscribe()
{
}

void OsAccountsManagerImpl::OnOsAccountSaAdd()
{
}

void OsAccountsManagerImpl::OnOsAccountSaRemove()
{
}

OsAccountsManager &OsAccountsManager::Instance()
{
    return OsAccountsManagerImpl::GetInstance();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS