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

#include "load_mode_handler_default.h"

#include "iservice_registry.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "system_param_manager.h"
#include "user_idm_database.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
LoadModeHandlerDefault::LoadModeHandlerDefault()
{
    IAM_LOGI("sa load mode is default");
}

void LoadModeHandlerDefault::StartSubscribe()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (isSubscribed_) {
        return;
    }

    isSubscribed_ = true;
}

void LoadModeHandlerDefault::OnFwkReady()
{
    IAM_LOGI("fwk ready");
    SystemParamManager::GetInstance().SetParamTwice(FWK_READY_KEY, FALSE_STR, TRUE_STR);
    CheckStartCompanionDeviceSa();
}

void LoadModeHandlerDefault::OnExecutorRegistered(AuthType authType, ExecutorRole executorRole)
{
    (void)authType;
    (void)executorRole;
}

void LoadModeHandlerDefault::OnExecutorUnregistered(AuthType authType, ExecutorRole executorRole)
{
    (void)authType;
    (void)executorRole;
}

void LoadModeHandlerDefault::OnCredentialUpdated(AuthType authType)
{
    if (authType != AuthType::COMPANION_DEVICE) {
        return;
    }
    IAM_LOGI("on credential updated authType %{public}d", authType);
    CheckStartCompanionDeviceSa();
}

void LoadModeHandlerDefault::OnPinAuthServiceReady()
{
}

void LoadModeHandlerDefault::OnPinAuthServiceStop()
{
}

void LoadModeHandlerDefault::OnDriverStart()
{
}

void LoadModeHandlerDefault::OnDriverStop()
{
}

void LoadModeHandlerDefault::SubscribeCredentialUpdatedListener()
{
}

void LoadModeHandlerDefault::OnCommonEventSaStart()
{
}

void LoadModeHandlerDefault::StartCheckServiceReadyTimer()
{
}

void LoadModeHandlerDefault::CancelCheckServiceReadyTimer()
{
}

void LoadModeHandlerDefault::TriggerAllServiceStart()
{
}

std::optional<bool> LoadModeHandlerDefault::AnyUserHasCompanionDeviceCredential()
{
    std::vector<AccountSA::OsAccountInfo> osAccountInfo;
#ifdef HAS_OS_ACCOUNT_PART
#ifndef ENABLE_TEST
    ErrCode errCode = AccountSA::OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfo);
    if (errCode != ERR_OK) {
        IAM_LOGE("QueryAllCreatedOsAccounts fail, errCode = %{public}d", errCode);
        return std::nullopt;
    }
#endif // ENABLE_TEST
#endif // HAS_OS_ACCOUNT_PART

    for (auto &info : osAccountInfo) {
        int32_t userId = info.GetLocalId();
        std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos;
        int32_t getCredRet =
            UserIdmDatabase::Instance().GetCredentialInfo(userId, AuthType::COMPANION_DEVICE, credInfos);
        if (getCredRet != SUCCESS) {
            IAM_LOGI("failed to get credential info ret %{public}d", getCredRet);
            continue;
        }

        if (!credInfos.empty()) {
            IAM_LOGI("user %{public}d companion device credential number %{public}zu", userId, credInfos.size());
            return true;
        }
        IAM_LOGI("user %{public}d has no companion device credential", userId);
    }
    return false;
}

void LoadModeHandlerDefault::CheckStartCompanionDeviceSa()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    IF_FALSE_LOGE_AND_RETURN(samgr != nullptr);

    sptr<IRemoteObject> object = samgr->CheckSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH);
    if (object != nullptr) {
        IAM_LOGI("companion device sa already started");
        return;
    }

    SystemParamManager::GetInstance().SetParam(CDA_IS_FUNCTION_READY_KEY, FALSE_STR);

    auto hasCredentialRet = AnyUserHasCompanionDeviceCredential();
    if (!hasCredentialRet.has_value()) {
        IAM_LOGE("fail to check companion device credential");
        return;
    }

    bool hasCompanionDeviceCredential = hasCredentialRet.value();
    if (!hasCompanionDeviceCredential) {
        IAM_LOGI("no user has companion device credential");
        return;
    }

    SystemParamManager::GetInstance().SetParamTwice(CDA_START_SA_KEY, FALSE_STR, TRUE_STR);
    IAM_LOGI("start companion device sa");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
