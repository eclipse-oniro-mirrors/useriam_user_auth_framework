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

#include "load_mode_handler_dynamic.h"

#include "os_account_manager.h"
#include "system_ability_definition.h"

#include "driver_load_manager.h"
#include "driver_state_manager.h"
#include "hisysevent_adapter.h"
#include "relative_timer.h"
#include "service_unload_manager.h"
#include "system_param_manager.h"
#include "user_idm_database.h"

#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_LOAD_MODE_HANDLER_DYNAMIC

namespace OHOS {
namespace UserIam {
namespace UserAuth {
constexpr uint32_t WAIT_TIME_FOR_SERVICE_READY = 5000;
const std::string MANAGE_USER_IDM = "ohos.permission.MANAGE_USER_IDM";

class CredentialUpdatedListener : public EventFwk::CommonEventSubscriber {
public:
    explicit CredentialUpdatedListener(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
        : EventFwk::CommonEventSubscriber(subscribeInfo) {}
    ~CredentialUpdatedListener() = default;
    
    void OnReceiveEvent(const EventFwk::CommonEventData &eventData) override
    {
        IAM_LOGI("start");
        const EventFwk::Want &want = eventData.GetWant();
        std::string action = want.GetAction();
        IAM_LOGI("receive event %{public}s", action.c_str());
        if (action != "USER_CREDENTIAL_UPDATED_EVENT") {
            return;
        }
        std::string authType = want.GetStringParam("authType");
        if (authType != std::to_string(PIN)) {
            return;
        }
        LoadModeHandler::GetInstance().OnCredentialUpdated(PIN);
    }
};

LoadModeHandlerDynamic::LoadModeHandlerDynamic()
{
    IAM_LOGI("sa load mode is dynamic");
    
    SubscribeCommonEventServiceListener();
    
    DriverStateManager::GetInstance().RegisterDriverStartCallback([]() {
        LoadModeHandler::GetInstance().OnDriverStart();
    });
    DriverStateManager::GetInstance().RegisterDriverStopCallback([]() {
        LoadModeHandler::GetInstance().OnDriverStop();
    });
}

void LoadModeHandlerDynamic::SubscribeCredentialUpdatedListener()
{
    IAM_LOGI("start");
    EventFwk::MatchingSkills matchSkills;
    matchSkills.AddEvent("USER_CREDENTIAL_UPDATED_EVENT");
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchSkills);
    subscribeInfo.SetPermission(MANAGE_USER_IDM);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (credentialUpdatedListener_ == nullptr) {
        credentialUpdatedListener_ = Common::MakeShared<CredentialUpdatedListener>(subscribeInfo);
    }
    IF_FALSE_LOGE_AND_RETURN(credentialUpdatedListener_ != nullptr);
    bool subscribeRet = EventFwk::CommonEventManager::SubscribeCommonEvent(credentialUpdatedListener_);
    IF_FALSE_LOGE_AND_RETURN(subscribeRet == true);
}

void LoadModeHandlerDynamic::SubscribeCommonEventServiceListener()
{
    IAM_LOGI("enter");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    commonEventServiceListener_ = SystemAbilityListener::Subscribe(
        "CommonEventService", COMMON_EVENT_SERVICE_ID,
        []() {
            GetInstance().OnCommonEventSaStart();
        },
        nullptr);
    IF_FALSE_LOGE_AND_RETURN(commonEventServiceListener_ != nullptr);
}

void LoadModeHandlerDynamic::OnCommonEventSaStart()
{
    SubscribeCredentialUpdatedListener();
    OnCredentialUpdated(PIN);
}

void LoadModeHandlerDynamic::StartSubscribe()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (isSubscribed_) {
        return;
    }

    DriverLoadManager::GetInstance().StartSubscribe();
    ServiceUnloadManager::GetInstance().StartSubscribe();

    if (pinAuthServiceListener_ == nullptr) {
        pinAuthServiceListener_ = SystemAbilityListener::Subscribe(
            "PinAuthService", SUBSYS_USERIAM_SYS_ABILITY_PINAUTH,
            []() { LoadModeHandler::GetInstance().OnPinAuthServiceReady(); },
            []() { LoadModeHandler::GetInstance().OnPinAuthServiceStop(); });
    }

    IF_FALSE_LOGE_AND_RETURN(pinAuthServiceListener_ != nullptr);

    isSubscribed_ = true;
    IAM_LOGI("start subscribe success");
}

void LoadModeHandlerDynamic::OnFwkReady()
{
    IAM_LOGI("fwk ready");
    RefreshIsPinEnrolled(true);
    SystemParamManager::GetInstance().SetParam(IS_CREDENTIAL_CHECKED_KEY, TRUE_STR);
    bool isStopSa = false;
    ServiceUnloadManager::GetInstance().OnFwkReady(isStopSa);
    if (!isStopSa) {
        SystemParamManager::GetInstance().SetParamTwice(FWK_READY_KEY, FALSE_STR, TRUE_STR);
    }
}

void LoadModeHandlerDynamic::OnExecutorRegistered(AuthType authType, ExecutorRole executorRole)
{
    if (authType != AuthType::PIN || executorRole != ExecutorRole::ALL_IN_ONE) {
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("executor registered authType %{public}d, executorRole %{public}d", authType, executorRole);
    isExecutorRegistered_ = true;
    RefreshIsPinFunctionReady();
}

void LoadModeHandlerDynamic::OnExecutorUnregistered(AuthType authType, ExecutorRole executorRole)
{
    if (authType != AuthType::PIN || executorRole != ExecutorRole::ALL_IN_ONE) {
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("executor unregistered authType %{public}d, executorRole %{public}d", authType, executorRole);
    isExecutorRegistered_ = false;
    RefreshIsPinFunctionReady();
}

void LoadModeHandlerDynamic::OnPinAuthServiceReady()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("on pin auth service ready");
    isPinAuthServiceReady_ = true;
    RefreshIsPinFunctionReady();
}

void LoadModeHandlerDynamic::OnPinAuthServiceStop()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("on pin auth service stop");
    isPinAuthServiceReady_ = false;

    RefreshIsPinFunctionReady();
    bool isPinEnrolled = SystemParamManager::GetInstance().GetParam(IS_PIN_ENROLLED_KEY, FALSE_STR) == TRUE_STR;
    if (isPinEnrolled) {
        IAM_LOGI("pin auth service down, pin enrolled, wait fwk ready");
    } else {
        bool isStopSa = SystemParamManager::GetInstance().GetParam(STOP_SA_KEY, FALSE_STR) == TRUE_STR;
        if (isStopSa) {
            IAM_LOGI("Sa is stopping, not need stop sa");
        } else {
            IAM_LOGI("pin auth service down, pin not enrolled, stop sa");
            SystemParamManager::GetInstance().SetParamTwice(STOP_SA_KEY, FALSE_STR, TRUE_STR);
        }
    }
}

void LoadModeHandlerDynamic::RefreshIsPinFunctionReady()
{
    bool isPinFunctionReady = isExecutorRegistered_ && isPinAuthServiceReady_;
    IAM_LOGI("is pin function ready %{public}s", isPinFunctionReady ? TRUE_STR : FALSE_STR);
    SystemParamManager::GetInstance().SetParam(IS_PIN_FUNCTION_READY_KEY, isPinFunctionReady ? TRUE_STR : FALSE_STR);
}

void LoadModeHandlerDynamic::OnCredentialUpdated(AuthType authType)
{
    if (authType != AuthType::PIN) {
        return;
    }
    IAM_LOGI("on credential updated authType %{public}d", authType);
    RefreshIsPinEnrolled(false);
}

std::optional<bool> LoadModeHandlerDynamic::AnyUserHasPinCredential()
{
    std::vector<AccountSA::OsAccountInfo> osAccountInfo;
    ErrCode errCode = AccountSA::OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfo);
    if (errCode != ERR_OK) {
        IAM_LOGE("QueryAllCreatedOsAccounts fail, errCode = %{public}d", errCode);
        return std::nullopt;
    }

    for (auto &info : osAccountInfo) {
        int32_t userId = info.GetLocalId();
        std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos;
        int32_t getCredRet = UserIdmDatabase::Instance().GetCredentialInfo(userId, AuthType::PIN, credInfos);
        if (getCredRet != SUCCESS) {
            // it's possible that the user has no credential
            IAM_LOGI("failed to get credential info ret %{public}d", getCredRet);
            if (getCredRet == INVALID_HDI_INTERFACE) {
                return std::nullopt;
            }
            continue;
        }

        if (!credInfos.empty()) {
            IAM_LOGI("user %{public}d pin credential number %{public}zu", userId, credInfos.size());
            return true;
        }
        IAM_LOGI("user %{public}d has no pin credential", userId);
    }
    return false;
}

void LoadModeHandlerDynamic::RefreshIsPinEnrolled(bool shouldReportBigData)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto ret = AnyUserHasPinCredential();
    if (!ret.has_value()) {
        IAM_LOGE("fail to refresh isPinEnrolled");
        return;
    }

    isPinEnrolled_ = *ret;
    IAM_LOGI("is pin enrolled %{public}s", isPinEnrolled_ ? TRUE_STR : FALSE_STR);
    if (shouldReportBigData) {
        bool isPinEnrolled = SystemParamManager::GetInstance().GetParam(IS_PIN_ENROLLED_KEY, FALSE_STR) == TRUE_STR;
        if (isPinEnrolled_ != isPinEnrolled) {
            bool preStatus = isPinEnrolled;
            bool updatedStatus = isPinEnrolled_;
            IsCredentialEnrolledMismatchTrace isCredentialEnrolledMismatchTraceInfo = {};
            isCredentialEnrolledMismatchTraceInfo.authType = AuthType::PIN;
            isCredentialEnrolledMismatchTraceInfo.preStatus = preStatus;
            isCredentialEnrolledMismatchTraceInfo.updatedStatus = updatedStatus;
            UserIam::UserAuth::ReportIsCredentialEnrolledMismatch(isCredentialEnrolledMismatchTraceInfo);
        }
    }

    SystemParamManager::GetInstance().SetParam(IS_PIN_ENROLLED_KEY, isPinEnrolled_ ? TRUE_STR : FALSE_STR);
}

void LoadModeHandlerDynamic::OnDriverStart()
{
    IAM_LOGI("on driver start");
    DriverLoadManager::GetInstance().OnDriverStart();
}

void LoadModeHandlerDynamic::OnDriverStop()
{
    IAM_LOGI("on driver stop");
    DriverLoadManager::GetInstance().OnDriverStop();
}

void LoadModeHandlerDynamic::StartCheckServiceReadyTimer()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (checkServiceReadyTimerId_.has_value()) {
        IAM_LOGI("timer already start");
        return;
    }

    checkServiceReadyTimerId_ = RelativeTimer::GetInstance().Register([]() {
        LoadModeHandler::GetInstance().TriggerAllServiceStart();
    }, WAIT_TIME_FOR_SERVICE_READY);
}

void LoadModeHandlerDynamic::CancelCheckServiceReadyTimer()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!checkServiceReadyTimerId_.has_value()) {
        IAM_LOGI("timer is null");
        return;
    }

    RelativeTimer::GetInstance().Unregister(checkServiceReadyTimerId_.value());
    checkServiceReadyTimerId_ = std::nullopt;
}

void LoadModeHandlerDynamic::TriggerAllServiceStart()
{
    IAM_LOGI("start");
    CancelCheckServiceReadyTimer();
    if (SystemParamManager::GetInstance().GetParam(STOP_SA_KEY, FALSE_STR) == TRUE_STR) {
        IAM_LOGE("service already stop");
        return;
    }

    IAM_LOGI("trigger all service start");
    SystemParamManager::GetInstance().SetParamTwice(START_SA_KEY, FALSE_STR, TRUE_STR);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
