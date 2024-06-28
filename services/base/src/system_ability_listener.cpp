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

#include "system_ability_listener.h"

#include "if_system_ability_manager.h"
#include "iservice_registry.h"

#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
SystemAbilityListener::SystemAbilityListener(std::string name, int32_t systemAbilityId,
    AddFunc addFunc, RemoveFunc removeFunc)
    : name_(name), systemAbilityId_(systemAbilityId), addFunc_(addFunc), removeFunc_(removeFunc)
{
    IAM_LOGI("start.");
}

void SystemAbilityListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    IAM_LOGI("start.");
    if (systemAbilityId != systemAbilityId_) {
        IAM_LOGI("systemAbilityId is not same.");
        return;
    }

    if (addFunc_ != nullptr) {
        addFunc_();
        IAM_LOGI("addFunc_ proc.");
    }
}
    
void SystemAbilityListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    IAM_LOGI("start.");
    if (systemAbilityId != systemAbilityId_) {
        IAM_LOGI("systemAbilityId is not same.");
        return;
    }

    if (removeFunc_ != nullptr) {
        removeFunc_();
        IAM_LOGI("removeFunc_ proc.");
    }
}

sptr<SystemAbilityListener> SystemAbilityListener::Subscribe(std::string name, int32_t systemAbilityId,
    AddFunc addFunc, RemoveFunc removeFunc)
{
    IAM_LOGI("start name:%{public}s, systemAbilityId::%{public}d", name.c_str(), systemAbilityId);
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    IF_FALSE_LOGE_AND_RETURN_VAL(sam != nullptr, nullptr);

    sptr<SystemAbilityListener> listener(
        new (std::nothrow) SystemAbilityListener(name, systemAbilityId, addFunc, removeFunc));
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, nullptr);

    int32_t ret = sam->SubscribeSystemAbility(systemAbilityId, listener);
    if (ret != ERR_OK) {
        IAM_LOGE("SubscribeSystemAbility fail, name:%{public}s, systemAbilityId::%{public}d",
            name.c_str(), systemAbilityId);
        return nullptr;
    }

    IAM_LOGI("Subscribe service name:%{public}s success", name.c_str());
    return listener;
}

int32_t SystemAbilityListener::UnSubscribe(int32_t systemAbilityId, sptr<SystemAbilityListener> &listener)
{
    IAM_LOGI("start systemAbilityId::%{public}d", systemAbilityId);
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    IF_FALSE_LOGE_AND_RETURN_VAL(sam != nullptr, ERR_OK);

    int32_t ret = sam->UnSubscribeSystemAbility(systemAbilityId, listener);
    if (ret != ERR_OK) {
        IAM_LOGE("UnSubscribeSystemAbility fail.");
        return ret;
    }

    IAM_LOGI("UnSubscribe service success");
    return ret;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
