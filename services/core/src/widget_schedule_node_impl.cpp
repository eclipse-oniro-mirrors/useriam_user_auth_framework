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
#include "widget_schedule_node_impl.h"

#include <mutex>
#include <sstream>

#include "nocopyable.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_para2str.h"
#include "iam_common_defines.h"
#include "relative_timer.h"
#include "user_auth_common_defines.h"

#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
WidgetScheduleNodeImpl::WidgetScheduleNodeImpl()
{
    machine_ = MakeFiniteStateMachine();
    if (machine_ == nullptr) {
        IAM_LOGE("Failed to create make FSM of widget schedule");
        return;
    }
    threadHandler_ = ThreadHandler::GetSingleThreadInstance();
    machine_->SetThreadHandler(threadHandler_);
}

std::shared_ptr<FiniteStateMachine> WidgetScheduleNodeImpl::MakeFiniteStateMachine()
{
    auto builder = FiniteStateMachine::Builder::New("widget_schedule", S_WIDGET_INIT);
    if (builder == nullptr) {
        return nullptr;
    }
    BuildInitStateTransitions(builder);
    BuildWaitingStateTransitions(builder);
    BuildAuthRunningStateTransitions(builder);
    BuildReloadWaitingStateTransitions(builder);
    BuildParamWaitingStateTransitions(builder);
    BuildAuthFinishedStateTransitions(builder);
    return builder->Build();
}

void WidgetScheduleNodeImpl::BuildInitStateTransitions(std::shared_ptr<FiniteStateMachine::Builder> &builder)
{
    builder->MakeTransition(S_WIDGET_INIT, E_GET_REMOTE_AUTH_PARAM, S_WIDGET_PARAM_WAITING,
        [this](FiniteStateMachine &machine, uint32_t event) { OnGetRemoteAuthParam(machine, event); });
    builder->MakeTransition(S_WIDGET_INIT, E_START_WIDGET, S_WIDGET_WAITING,
        [this](FiniteStateMachine &machine, uint32_t event) { OnStartSchedule(machine, event); });
    builder->MakeTransition(S_WIDGET_INIT, E_START_DIRECT_AUTH, S_WIDGET_AUTH_RUNNING,
        [this](FiniteStateMachine &machine, uint32_t event) { OnStartDirectAuth(machine, event); });
    builder->MakeTransition(S_WIDGET_INIT, E_WIDGET_RELEASE, S_WIDGET_RELEASED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnWidgetRelease(machine, event); });
}

void WidgetScheduleNodeImpl::BuildWaitingStateTransitions(std::shared_ptr<FiniteStateMachine::Builder> &builder)
{
    builder->MakeTransition(S_WIDGET_WAITING, E_START_AUTH, S_WIDGET_AUTH_RUNNING,
        [this](FiniteStateMachine &machine, uint32_t event) { OnStartAuth(machine, event); });
    builder->MakeTransition(S_WIDGET_WAITING, E_CANCEL_AUTH, S_WIDGET_AUTH_FINISHED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnStopSchedule(machine, event); });
    builder->MakeTransition(S_WIDGET_WAITING, E_NAVI_PIN_AUTH, S_WIDGET_AUTH_FINISHED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnNaviPinAuth(machine, event); });
    builder->MakeTransition(S_WIDGET_WAITING, E_WIDGET_PARA_INVALID, S_WIDGET_AUTH_FINISHED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnWidgetParaInvalid(machine, event); });
    builder->MakeTransition(S_WIDGET_WAITING, E_WIDGET_RELOAD, S_WIDGET_RELOAD_WAITING,
        [this](FiniteStateMachine &machine, uint32_t event) { OnWidgetReloadInit(machine, event); });
    builder->MakeTransition(S_WIDGET_WAITING, E_WIDGET_RELEASE, S_WIDGET_RELEASED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnWidgetRelease(machine, event); });
}

void WidgetScheduleNodeImpl::BuildAuthRunningStateTransitions(std::shared_ptr<FiniteStateMachine::Builder> &builder)
{
    builder->MakeTransition(S_WIDGET_AUTH_RUNNING, E_COMPLETE_AUTH, S_WIDGET_AUTH_FINISHED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnSuccessAuth(machine, event); });
    builder->MakeTransition(S_WIDGET_AUTH_RUNNING, E_STOP_AUTH, S_WIDGET_AUTH_FINISHED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnFailAuth(machine, event); });
    builder->MakeTransition(S_WIDGET_AUTH_RUNNING, E_CANCEL_AUTH, S_WIDGET_AUTH_FINISHED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnStopSchedule(machine, event); });
    builder->MakeTransition(S_WIDGET_AUTH_RUNNING, E_NAVI_PIN_AUTH, S_WIDGET_AUTH_FINISHED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnNaviPinAuth(machine, event); });
    builder->MakeTransition(S_WIDGET_AUTH_RUNNING, E_START_AUTH, S_WIDGET_AUTH_RUNNING,
        [this](FiniteStateMachine &machine, uint32_t event) { OnStartAuth(machine, event); });
    builder->MakeTransition(S_WIDGET_AUTH_RUNNING, E_UPDATE_AUTH, S_WIDGET_AUTH_RUNNING,
        [this](FiniteStateMachine &machine, uint32_t event) { OnStopAuthList(machine, event); });
    builder->MakeTransition(S_WIDGET_AUTH_RUNNING, E_WIDGET_PARA_INVALID, S_WIDGET_AUTH_FINISHED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnWidgetParaInvalid(machine, event); });
    builder->MakeTransition(S_WIDGET_AUTH_RUNNING, E_WIDGET_RELOAD, S_WIDGET_RELOAD_WAITING,
        [this](FiniteStateMachine &machine, uint32_t event) { OnWidgetReloadInit(machine, event); });
    builder->MakeTransition(S_WIDGET_AUTH_RUNNING, E_WIDGET_RELEASE, S_WIDGET_RELEASED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnWidgetRelease(machine, event); });
}

void WidgetScheduleNodeImpl::BuildReloadWaitingStateTransitions(std::shared_ptr<FiniteStateMachine::Builder> &builder)
{
    builder->MakeTransition(S_WIDGET_RELOAD_WAITING, E_CANCEL_AUTH, S_WIDGET_WAITING,
        [this](FiniteStateMachine &machine, uint32_t event) { OnWidgetReload(machine, event); });
    builder->MakeTransition(S_WIDGET_RELOAD_WAITING, E_WIDGET_RELEASE, S_WIDGET_RELEASED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnWidgetRelease(machine, event); });
}

void WidgetScheduleNodeImpl::BuildParamWaitingStateTransitions(std::shared_ptr<FiniteStateMachine::Builder> &builder)
{
    builder->MakeTransition(S_WIDGET_PARAM_WAITING, E_START_WIDGET, S_WIDGET_WAITING,
        [this](FiniteStateMachine &machine, uint32_t event) { OnStartSchedule(machine, event); });
    builder->MakeTransition(S_WIDGET_PARAM_WAITING, E_WIDGET_RELEASE, S_WIDGET_RELEASED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnWidgetRelease(machine, event); });
}

void WidgetScheduleNodeImpl::BuildAuthFinishedStateTransitions(std::shared_ptr<FiniteStateMachine::Builder> &builder)
{
    builder->MakeTransition(S_WIDGET_AUTH_FINISHED, E_WIDGET_RELEASE, S_WIDGET_RELEASED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnWidgetRelease(machine, event); });
}

bool WidgetScheduleNodeImpl::TryKickMachine(Event event)
{
    if (machine_ == nullptr) {
        IAM_LOGE("Invalid FSM of widget schedule");
        return false;
    }
    machine_->Schedule(event);
    return true;
}

bool WidgetScheduleNodeImpl::GetRemoteAuthParam()
{
    iamHitraceHelper_ = Common::MakeShared<IamHitraceHelper>("widget_get_remote_auth_param");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!TryKickMachine(E_GET_REMOTE_AUTH_PARAM)) {
            IAM_LOGE("TryKickMachine E_GET_REMOTE_AUTH_PARAM failed");
            return false;
        }
    }
    return true;
}

bool WidgetScheduleNodeImpl::StartSchedule()
{
    iamHitraceHelper_ = Common::MakeShared<IamHitraceHelper>("widget_schedule");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!TryKickMachine(E_START_WIDGET)) {
            return false;
        }
    }
    return true;
}

bool WidgetScheduleNodeImpl::StartDirectAuth()
{
    iamHitraceHelper_ = Common::MakeShared<IamHitraceHelper>("widget_direct_auth");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!TryKickMachine(E_START_DIRECT_AUTH)) {
            IAM_LOGE("TryKickMachine E_START_DIRECT_AUTH failed");
            return false;
        }
    }
    return true;
}

bool WidgetScheduleNodeImpl::StopSchedule()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return TryKickMachine(E_CANCEL_AUTH);
}

bool WidgetScheduleNodeImpl::ClearSchedule()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return TryKickMachine(E_WIDGET_RELEASE);
}

bool WidgetScheduleNodeImpl::StartAuthList(const std::vector<AuthType> &authTypeList, bool endAfterFirstFail,
    AuthIntent authIntent)
{
    std::lock_guard<std::mutex> lock(mutex_);
    startAuthTypeList_.clear();
    for (auto authType : authTypeList) {
        startAuthTypeList_.emplace_back(authType);
        IAM_LOGI("Command(type:%{public}d) on result start.", authType);
    }
    endAfterFirstFail_ = endAfterFirstFail;
    authIntent_ = authIntent;
    return TryKickMachine(E_START_AUTH);
}

bool WidgetScheduleNodeImpl::StopAuthList(const std::vector<AuthType> &authTypeList)
{
    std::lock_guard<std::mutex> lock(mutex_);
    stopAuthTypeList_ = authTypeList;
    return TryKickMachine(E_UPDATE_AUTH);
}

bool WidgetScheduleNodeImpl::SuccessAuth(AuthType authType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    successAuthType_ = authType;
    IAM_LOGI("success %{public}d.", E_COMPLETE_AUTH);
    return TryKickMachine(E_COMPLETE_AUTH);
}

bool WidgetScheduleNodeImpl::FailAuth(AuthType authType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    failAuthType_ = authType;
    IAM_LOGI("fail %{public}d.", E_STOP_AUTH);
    return TryKickMachine(E_STOP_AUTH);
}

bool WidgetScheduleNodeImpl::NaviPinAuth()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return TryKickMachine(E_NAVI_PIN_AUTH);
}

bool WidgetScheduleNodeImpl::WidgetParaInvalid()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return TryKickMachine(E_WIDGET_PARA_INVALID);
}

bool WidgetScheduleNodeImpl::WidgetReload(uint32_t orientation, uint32_t needRotate, uint32_t alreadyLoad,
    AuthType &rotateAuthType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    orientation_ = orientation;
    needRotate_ = needRotate;
    alreadyLoad_ = alreadyLoad;
    rotateAuthType_ = rotateAuthType;
    return TryKickMachine(E_WIDGET_RELOAD);
}

void WidgetScheduleNodeImpl::SetCallback(std::shared_ptr<WidgetScheduleNodeCallback> callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = callback;
}

void WidgetScheduleNodeImpl::OnGetRemoteAuthParam(FiniteStateMachine &machine, uint32_t event)
{
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    if (!callback->GetRemoteAuthParam()) {
        IAM_LOGE("Failed to get remote auth param");
    }
}

void WidgetScheduleNodeImpl::OnStartSchedule(FiniteStateMachine &machine, uint32_t event)
{
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    if (!callback->LaunchWidget()) {
        IAM_LOGE("Failed to launch widget, cancel Auth");
        StopSchedule();
    }
}

void WidgetScheduleNodeImpl::OnStopSchedule(FiniteStateMachine &machine, uint32_t event)
{
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    callback->EndAuthAsCancel();
    iamHitraceHelper_ = nullptr;
}

void WidgetScheduleNodeImpl::OnStartDirectAuth(FiniteStateMachine &machine, uint32_t event)
{
    IAM_LOGI("start direct auth (skip widget UI)");
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    std::set<AuthType> startAuthTypeSet;
    for (auto authType : startAuthTypeList_) {
        if (runningAuthTypeSet_.find(authType) == runningAuthTypeSet_.end()) {
            runningAuthTypeSet_.emplace(authType);
            startAuthTypeSet.emplace(authType);
            IAM_LOGI("direct auth type: %{public}d, added to runningAuthTypeSet_", static_cast<int32_t>(authType));
        }
    }
    callback->ExecuteAuthList(startAuthTypeSet, endAfterFirstFail_, authIntent_);
}

void WidgetScheduleNodeImpl::OnStartAuth(FiniteStateMachine &machine, uint32_t event)
{
    IAM_LOGI("OnStartAuth start");
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    std::set<AuthType> startAuthTypeSet;
    for (auto authType : startAuthTypeList_) {
        if (runningAuthTypeSet_.find(authType) == runningAuthTypeSet_.end()) {
            startAuthTypeSet.emplace(authType);
            runningAuthTypeSet_.emplace(authType);
            IAM_LOGI("emplace authType %{public}d to runningAuthTypeSet_", static_cast<int32_t>(authType));
        }
    }
    callback->ExecuteAuthList(startAuthTypeSet, endAfterFirstFail_, authIntent_);
}

void WidgetScheduleNodeImpl::OnStopAuthList(FiniteStateMachine &machine, uint32_t event)
{
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    for (auto authType : stopAuthTypeList_) {
        runningAuthTypeSet_.erase(authType);
    }
    callback->StopAuthList(stopAuthTypeList_);
}

void WidgetScheduleNodeImpl::OnSuccessAuth(FiniteStateMachine &machine, uint32_t event)
{
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    runningAuthTypeSet_.erase(successAuthType_);
    callback->SuccessAuth(successAuthType_);
}

void WidgetScheduleNodeImpl::OnFailAuth(FiniteStateMachine &machine, uint32_t event)
{
    IAM_LOGI("OnFailAuth start");
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    runningAuthTypeSet_.erase(failAuthType_);
    callback->FailAuth(failAuthType_);
}

void WidgetScheduleNodeImpl::OnNaviPinAuth(FiniteStateMachine &machine, uint32_t event)
{
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    callback->EndAuthAsNaviPin();
}

void WidgetScheduleNodeImpl::OnWidgetParaInvalid(FiniteStateMachine &machine, uint32_t event)
{
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    callback->EndAuthAsWidgetParaInvalid();
}

void WidgetScheduleNodeImpl::OnWidgetReloadInit(FiniteStateMachine &machine, uint32_t event)
{
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    IAM_LOGI("Widget need reload, init");
    callback->AuthWidgetReloadInit();
}

void WidgetScheduleNodeImpl::OnWidgetReload(FiniteStateMachine &machine, uint32_t event)
{
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    IAM_LOGI("Widget need reload");
    const uint32_t reloadInitMs = 100;
    auto sleepTime = std::chrono::milliseconds(reloadInitMs);
    std::this_thread::sleep_for(sleepTime);
    if (!callback->AuthWidgetReload(orientation_, needRotate_, alreadyLoad_, rotateAuthType_)) {
        IAM_LOGE("Failed to reload widget, cancel Auth");
        StopSchedule();
    }
}

void WidgetScheduleNodeImpl::OnWidgetRelease(FiniteStateMachine &machine, uint32_t event)
{
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    IAM_LOGI("clear schedule");
    callback->ClearSchedule();
}

void WidgetScheduleNodeImpl::SendAuthTipInfo(const std::vector<AuthType> &authTypeList, int32_t tipCode)
{
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    IAM_LOGI("send mid auth result");
    for (auto &authType : authTypeList) {
        callback->SendAuthTipInfo(authType, tipCode);
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
