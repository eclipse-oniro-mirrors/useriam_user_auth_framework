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

#include "mock_system_ability_listener.h"

#include "iam_logger.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_SYSTEM_ABILITY_LISTENER
namespace OHOS {
namespace UserIam {
namespace UserAuth {
SystemAbilityListener::SystemAbilityListener(std::string name, int32_t systemAbilityId,
    AddFunc addFunc, RemoveFunc removeFunc)
{
    IAM_LOGI("start.");
}

void SystemAbilityListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    IAM_LOGI("start.");
}
    
void SystemAbilityListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    IAM_LOGI("start.");
}

sptr<SystemAbilityListener> SystemAbilityListener::Subscribe(std::string name, int32_t systemAbilityId,
    AddFunc addFunc, RemoveFunc removeFunc)
{
    IAM_LOGI("start.");
    return nullptr;
}

int32_t SystemAbilityListener::UnSubscribe(int32_t systemAbilityId, sptr<SystemAbilityListener> &listener)
{
    IAM_LOGI("start.");
    return 0;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
