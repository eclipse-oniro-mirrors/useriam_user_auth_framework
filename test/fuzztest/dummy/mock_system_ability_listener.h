/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MOCK_SYSTEM_ABILITY_SERVICE_STATUS_LISTENER_H
#define MOCK_SYSTEM_ABILITY_SERVICE_STATUS_LISTENER_H

#include "system_ability_status_change_stub.h"

#include "iam_check.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class SystemAbilityListener : public OHOS::SystemAbilityStatusChangeStub, public NoCopyable {
public:
    using AddFunc = std::function<void(void)>;
    using RemoveFunc = std::function<void(void)>;
    SystemAbilityListener(std::string name, int32_t systemAbilityId,
         AddFunc addFunc, RemoveFunc removeFunc);
    ~SystemAbilityListener() override {};
    
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    static sptr<SystemAbilityListener> Subscribe(std::string name, int32_t systemAbilityId,
         AddFunc addFunc, RemoveFunc removeFunc);
    static int32_t UnSubscribe(int32_t systemAbilityId, sptr<SystemAbilityListener> &listener);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MOCK_SYSTEM_ABILITY_SERVICE_STATUS_LISTENER_H