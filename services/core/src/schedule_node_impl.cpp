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
#include "schedule_node_impl.h"

#include <mutex>
#include <sstream>

#include "nocopyable.h"

#include "attributes.h"
#include "hdi_wrapper.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_para2str.h"
#include "iam_common_defines.h"
#include "relative_timer.h"
#include "schedule_resource_node_listener.h"

#define LOG_FILE_ID LOG_FILE_SCHEDULE_NODE_IMPL
#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ScheduleNodeImpl::ScheduleNodeImpl(ScheduleInfo &info) : info_(std::move(info))
{
    machine_ = MakeFiniteStateMachine();
    if (machine_ && info_.threadHandler == nullptr) {
        info_.threadHandler = ThreadHandler::GetSingleThreadInstance();
        machine_->SetThreadHandler(info_.threadHandler);
    }
}

ScheduleNodeImpl::~ScheduleNodeImpl()
{
    if (resourceNodePoolListener_ != nullptr) {
        ResourceNodePool::Instance().DeregisterResourceNodePoolListener(resourceNodePoolListener_);
    }
}

void ScheduleNodeImpl::GetScheduleAttribute(bool isVerifier, Attributes &attribute) const
{
    attribute.SetInt32Value(Attributes::ATTR_SCHEDULE_MODE, info_.scheduleMode);

    if (info_.tokenId.has_value()) {
        attribute.SetUint32Value(Attributes::ATTR_ACCESS_TOKEN_ID, info_.tokenId.value());
    }

    if (info_.pinSubType != 0) {
        attribute.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, info_.pinSubType);
    }

    attribute.SetUint32Value(Attributes::ATTR_COLLECTOR_TOKEN_ID, info_.collectorTokenId);
    attribute.SetBoolValue(Attributes::ATTR_END_AFTER_FIRST_FAIL, info_.endAfterFirstFail);
    IAM_LOGI("verifier message length = %{public}zu, collector message length = %{public}zu",
        info_.verifierMessage.size(), info_.collectorMessage.size());

    if (isVerifier) {
        attribute.SetInt32Value(Attributes::ATTR_AUTH_INTENTION, info_.authIntent);
        attribute.SetInt32Value(Attributes::ATTR_USER_ID, info_.userId);
        attribute.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, info_.verifierMessage);
    } else {
        attribute.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, info_.collectorMessage);
    }

    if (!info_.templateIdList.empty()) {
        attribute.SetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, info_.templateIdList);
        if (info_.templateIdList.size() == 1) {
            attribute.SetUint64Value(Attributes::ATTR_TEMPLATE_ID, *info_.templateIdList.begin());
        }
    }

    if (!info_.additionalInfo.empty()) {
        attribute.SetStringValue(Attributes::ATTR_ADDITIONAL_INFO, info_.additionalInfo);
    }

    if (!info_.title.empty()) {
        attribute.SetStringValue(Attributes::ATTR_WIDGET_TITLE, info_.title);
    }

    attribute.SetInt32Value(Attributes::ATTR_AUTH_SCENE, static_cast<int32_t>(info_.authScene));
}

uint64_t ScheduleNodeImpl::GetScheduleId() const
{
    return info_.scheduleId;
}

uint64_t ScheduleNodeImpl::GetContextId() const
{
    return info_.contextId;
}

AuthType ScheduleNodeImpl::GetAuthType() const
{
    return info_.authType;
}

uint64_t ScheduleNodeImpl::GetExecutorMatcher() const
{
    return info_.executorMatcher;
}

ScheduleMode ScheduleNodeImpl::GetScheduleMode() const
{
    return info_.scheduleMode;
}

std::weak_ptr<ResourceNode> ScheduleNodeImpl::GetCollectorExecutor() const
{
    return info_.collector;
}

std::weak_ptr<ResourceNode> ScheduleNodeImpl::GetVerifyExecutor() const
{
    return info_.verifier;
}

std::optional<std::vector<uint64_t>> ScheduleNodeImpl::GetTemplateIdList() const
{
    if (info_.templateIdList.empty()) {
        return std::nullopt;
    }
    return info_.templateIdList;
}

ScheduleNode::State ScheduleNodeImpl::GetCurrentScheduleState() const
{
    if (machine_ == nullptr) {
        return S_INIT;
    }
    return static_cast<State>(machine_->GetCurrentState());
}

std::shared_ptr<ScheduleNodeCallback> ScheduleNodeImpl::GetScheduleCallback()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return info_.callback;
}

int32_t ScheduleNodeImpl::GetAuthIntent() const
{
    return info_.authIntent;
}

void ScheduleNodeImpl::ClearScheduleCallback()
{
    std::lock_guard<std::mutex> lock(mutex_);
    info_.callback = nullptr;
}

bool ScheduleNodeImpl::StartSchedule()
{
    iamHitraceHelper_ = Common::MakeShared<IamHitraceHelper>(GetDescription());
    {
        std::lock_guard<std::mutex> lock(mutex_);
        resourceNodePoolListener_ = Common::MakeShared<ScheduleResourceNodeListener>(weak_from_this());
        IF_FALSE_LOGE_AND_RETURN_VAL(resourceNodePoolListener_ != nullptr, false);
        bool registerRet = ResourceNodePool::Instance().RegisterResourceNodePoolListener(resourceNodePoolListener_);
        IF_FALSE_LOGE_AND_RETURN_VAL(registerRet, false);
        if (!TryKickMachine(E_START_AUTH)) {
            return false;
        }
    }
    StartTimer();
    return true;
}

bool ScheduleNodeImpl::StopSchedule()
{
    return StopSchedule(CANCELED);
}

bool ScheduleNodeImpl::StopSchedule(ResultCode errorCode)
{
    std::lock_guard<std::mutex> lock(mutex_);

    SetFwkResultCode(errorCode);
    IAM_LOGI("stop schedule %{public}s, error code %{public}d", GET_MASKED_STRING(info_.scheduleId).c_str(),
        errorCode);
    return TryKickMachine(E_STOP_AUTH);
}

bool ScheduleNodeImpl::SendMessage(ExecutorRole dstRole, const std::vector<uint8_t> &msg)
{
    Attributes attr(msg);
    if (dstRole == SCHEDULER) {
        int32_t tip;
        if (attr.GetInt32Value(Attributes::ATTR_TIP_INFO, tip)) {
            std::shared_ptr<ScheduleNodeCallback> callback = GetScheduleCallback();
            IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, false);
            callback->OnScheduleProcessed(dstRole, GetAuthType(), msg);
            return true;
        } else {
            int srcRole;
            std::vector<uint8_t> message;
            bool getAcquireRet = attr.GetInt32Value(Attributes::ATTR_SRC_ROLE, srcRole);
            IF_FALSE_LOGE_AND_RETURN_VAL(getAcquireRet, false);
            bool getExtraInfoRet = attr.GetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, message);
            IF_FALSE_LOGE_AND_RETURN_VAL(getExtraInfoRet, false);
            auto hdi = HdiWrapper::GetHdiInstance();
            IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, false);
            int sendMsgRet = hdi->SendMessage(GetScheduleId(), srcRole, message);
            IF_FALSE_LOGE_AND_RETURN_VAL(sendMsgRet == HDF_SUCCESS, false);
            return true;
        }
    }

    std::shared_ptr<ResourceNode> node = nullptr;
    if (dstRole == ALL_IN_ONE || dstRole == VERIFIER) {
        node = info_.verifier.lock();
    } else if (dstRole == COLLECTOR) {
        node = info_.collector.lock();
    }

    IF_FALSE_LOGE_AND_RETURN_VAL(node != nullptr, false);
    node->SendData(GetScheduleId(), attr);
    return true;
}

bool ScheduleNodeImpl::ContinueSchedule(ResultCode resultCode, const std::shared_ptr<Attributes> &finalResult)
{
    std::lock_guard<std::mutex> lock(mutex_);
    SetExecutorResultCode(resultCode);
    SetScheduleResult(finalResult);
    return TryKickMachine(E_SCHEDULE_RESULT_RECEIVED);
}

std::shared_ptr<FiniteStateMachine> ScheduleNodeImpl::MakeFiniteStateMachine()
{
    auto builder = FiniteStateMachine::Builder::New(GetDescription(), S_INIT);
    if (builder == nullptr) {
        return nullptr;
    }
    // S_INIT
    builder->MakeTransition(S_INIT, E_START_AUTH, S_VERIFY_STARING,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessBeginVerifier(machine, event); });

    // S_VERIFY_STARING
    builder->MakeTransition(S_VERIFY_STARING, E_VERIFY_STARTED_SUCCESS, S_COLLECT_STARING,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessBeginCollector(machine, event); });
    builder->MakeTransition(S_VERIFY_STARING, E_VERIFY_STARTED_FAILED, S_END,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessVerifierBeginFailed(machine, event); });
    builder->MakeTransition(S_VERIFY_STARING, E_SCHEDULE_RESULT_RECEIVED, S_END);
    builder->MakeTransition(S_VERIFY_STARING, E_STOP_AUTH, S_VERIFY_STOPPING,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessEndVerifier(machine, event); });
    builder->MakeTransition(S_VERIFY_STARING, E_TIME_OUT, S_VERIFY_STOPPING,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessEndVerifier(machine, event); });

    // S_COLLECT_STARING
    builder->MakeTransition(S_COLLECT_STARING, E_COLLECT_STARTED_SUCCESS, S_AUTH_PROCESSING);
    builder->MakeTransition(S_COLLECT_STARING, E_SCHEDULE_RESULT_RECEIVED, S_END);
    builder->MakeTransition(S_COLLECT_STARING, E_STOP_AUTH, S_COLLECT_STOPPING,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessEndCollector(machine, event); });

    // S_AUTH_PROCESSING
    builder->MakeTransition(S_AUTH_PROCESSING, E_SCHEDULE_RESULT_RECEIVED, S_END);
    builder->MakeTransition(S_AUTH_PROCESSING, E_STOP_AUTH, S_COLLECT_STOPPING,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessEndCollector(machine, event); });
    builder->MakeTransition(S_AUTH_PROCESSING, E_TIME_OUT, S_COLLECT_STOPPING,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessEndCollector(machine, event); });

    // S_COLLECT_STOPPING
    builder->MakeTransition(S_COLLECT_STOPPING, E_SCHEDULE_RESULT_RECEIVED, S_END);
    builder->MakeTransition(S_COLLECT_STOPPING, E_COLLECT_STOPPED_SUCCESS, S_VERIFY_STOPPING,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessEndVerifier(machine, event); });
    builder->MakeTransition(S_COLLECT_STOPPING, E_COLLECT_STOPPED_FAILED, S_VERIFY_STOPPING,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessEndVerifier(machine, event); });
    builder->MakeTransition(S_COLLECT_STOPPING, E_TIME_OUT, S_VERIFY_STOPPING,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessEndVerifier(machine, event); });

    // S_VERIFY_STOPPING
    builder->MakeTransition(S_VERIFY_STOPPING, E_SCHEDULE_RESULT_RECEIVED, S_END);
    builder->MakeTransition(S_VERIFY_STOPPING, E_VERIFY_STOPPED_SUCCESS, S_END);
    builder->MakeTransition(S_VERIFY_STOPPING, E_VERIFY_STOPPED_FAILED, S_END);
    builder->MakeTransition(S_VERIFY_STOPPING, E_TIME_OUT, S_END);

    // ENTERS
    builder->MakeOnStateEnter(S_AUTH_PROCESSING,
        [this](FiniteStateMachine &machine, uint32_t event) { OnScheduleProcessing(machine, event); });
    builder->MakeOnStateEnter(S_END,
        [this](FiniteStateMachine &machine, uint32_t event) { OnScheduleFinished(machine, event); });
    return builder->Build();
}

std::string ScheduleNodeImpl::GetDescription() const
{
    std::ostringstream ss;

    auto verifier = info_.verifier.lock();
    ss << "schedule type:" << (verifier ? Common::AuthTypeToStr(verifier->GetAuthType()) : "nullptr") <<
        " id:******" << std::hex << static_cast<uint16_t>(GetScheduleId());
    return ss.str();
}

bool ScheduleNodeImpl::TryKickMachine(Event event)
{
    if (machine_ == nullptr) {
        return false;
    }
    machine_->Schedule(event);
    return true;
}

void ScheduleNodeImpl::SetFwkResultCode(int32_t resultCode)
{
    fwkResultCode_ = resultCode;
}

void ScheduleNodeImpl::SetExecutorResultCode(int32_t resultCode)
{
    executorResultCode_ = resultCode;
}

void ScheduleNodeImpl::SetScheduleResult(const std::shared_ptr<Attributes> &scheduleResult)
{
    scheduleResult_ = scheduleResult;
}

void ScheduleNodeImpl::StartTimer()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (info_.expiredTime == 0 || timerId_ != 0) {
        return;
    }

    timerId_ = RelativeTimer::GetInstance().Register(
        [self = weak_from_this(), this] {
            if (self.lock()) {
                std::lock_guard<std::mutex> lock(mutex_);
                SetFwkResultCode(TIMEOUT);
                TryKickMachine(E_TIME_OUT);
            }
        },
        info_.expiredTime);
}

void ScheduleNodeImpl::StopTimer()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (timerId_ == 0) {
        return;
    }
    RelativeTimer::GetInstance().Unregister(timerId_);
    timerId_ = 0;
}

void ScheduleNodeImpl::ProcessBeginVerifier(FiniteStateMachine &machine, uint32_t event)
{
    auto collector = info_.collector.lock();
    auto verifier = info_.verifier.lock();
    if (collector == nullptr || verifier == nullptr) {
        SetFwkResultCode(GENERAL_ERROR);
        machine.Schedule(E_VERIFY_STARTED_FAILED);
        IAM_LOGE("invalid resource");
        return;
    }
    auto peerPk = collector->GetExecutorPublicKey();
    Attributes attr;
    GetScheduleAttribute(true, attr);
    auto result = verifier->BeginExecute(info_.scheduleId, peerPk, attr);
    if (result != SUCCESS) {
        IAM_LOGE("start verify failed, result = %{public}d", result);
        SetExecutorResultCode(result);
        machine.Schedule(E_VERIFY_STARTED_FAILED);
        return;
    }
    IAM_LOGD("start verify success");
    machine.Schedule(E_VERIFY_STARTED_SUCCESS);
}

void ScheduleNodeImpl::ProcessBeginCollector(FiniteStateMachine &machine, uint32_t event)
{
    auto collector = info_.collector.lock();
    auto verifier = info_.verifier.lock();
    if (collector == nullptr || verifier == nullptr) {
        SetFwkResultCode(GENERAL_ERROR);
        machine.Schedule(E_COLLECT_STARTED_FAILED);
        IAM_LOGE("invalid resource");
        return;
    }
    if (collector == verifier) {
        IAM_LOGD("all in one schedule, just wait the result");
        machine.Schedule(E_COLLECT_STARTED_SUCCESS);
        return;
    }

    auto peerPk = collector->GetExecutorPublicKey();
    Attributes attr;
    GetScheduleAttribute(false, attr);
    auto result = collector->BeginExecute(info_.scheduleId, peerPk, attr);
    if (result != SUCCESS) {
        IAM_LOGE("start collect failed, result = %{public}d", result);
        SetExecutorResultCode(result);
        machine.Schedule(E_COLLECT_STARTED_FAILED);
        return;
    }
    IAM_LOGD("start collect success");
    machine.Schedule(E_COLLECT_STARTED_SUCCESS);
    NotifyCollectorReady();
}

void ScheduleNodeImpl::NotifyCollectorReady()
{
    auto verifier = info_.verifier.lock();
    if (verifier == nullptr) {
        return;
    }

    Attributes attr;
    bool setPropertyModeRet = attr.SetInt32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_NOTIFY_COLLECTOR_READY);
    IF_FALSE_LOGE_AND_RETURN(setPropertyModeRet);
    bool setScheduleIdRet = attr.SetUint64Value(Attributes::ATTR_SCHEDULE_ID, GetScheduleId());
    IF_FALSE_LOGE_AND_RETURN(setScheduleIdRet);

    int32_t ret = verifier->SetProperty(attr);
    if (ret != SUCCESS) {
        IAM_LOGE("notify collector ready failed, result = %{public}d", ret);
    }
}

void ScheduleNodeImpl::ProcessVerifierBeginFailed(FiniteStateMachine &machine, uint32_t event)
{
    // just do nothing
}

void ScheduleNodeImpl::ProcessCollectorBeginFailed(FiniteStateMachine &machine, uint32_t event)
{
    // just do nothing
}

void ScheduleNodeImpl::ProcessScheduleResultReceived(FiniteStateMachine &machine, uint32_t event) const
{
    // just do nothing
}

void ScheduleNodeImpl::ProcessEndCollector(FiniteStateMachine &machine, uint32_t event)
{
    auto collector = info_.collector.lock();
    auto verifier = info_.verifier.lock();
    if (collector == nullptr || verifier == nullptr) {
        SetFwkResultCode(GENERAL_ERROR);
        machine.Schedule(E_COLLECT_STOPPED_FAILED);
        return;
    }
    if (collector == verifier) {
        IAM_LOGE("all in one schedule, just do noting");
        machine.Schedule(E_COLLECT_STOPPED_SUCCESS);
        return;
    }
    Attributes attr;
    auto result = collector->EndExecute(info_.scheduleId, attr);
    if (result != SUCCESS) {
        IAM_LOGE("end verify failed, result = %{public}d", result);
        SetExecutorResultCode(result);
        machine.Schedule(E_COLLECT_STOPPED_FAILED);
        return;
    }
    machine.Schedule(E_COLLECT_STOPPED_SUCCESS);
}

void ScheduleNodeImpl::ProcessEndVerifier(FiniteStateMachine &machine, uint32_t event)
{
    auto verifier = info_.verifier.lock();
    if (verifier == nullptr) {
        SetFwkResultCode(GENERAL_ERROR);
        machine.Schedule(E_VERIFY_STOPPED_FAILED);
        return;
    }
    Attributes attr;
    auto result = verifier->EndExecute(info_.scheduleId, attr);
    if (result != SUCCESS) {
        IAM_LOGE("end verify failed, result = %{public}d", result);
        SetExecutorResultCode(result);
        machine.Schedule(E_VERIFY_STOPPED_FAILED);
        return;
    }
    machine.Schedule(E_VERIFY_STOPPED_SUCCESS);
}

void ScheduleNodeImpl::OnScheduleProcessing(FiniteStateMachine &machine, uint32_t event)
{
    std::shared_ptr<ScheduleNodeCallback> callback = GetScheduleCallback();
    if (!callback) {
        return;
    }
    callback->OnScheduleStarted();
}

void ScheduleNodeImpl::OnScheduleFinished(FiniteStateMachine &machine, uint32_t event)
{
    StopTimer();
    std::shared_ptr<ScheduleNodeCallback> callback = GetScheduleCallback();
    if (!callback) {
        return;
    }

    iamHitraceHelper_ = nullptr;

    int32_t result = fwkResultCode_.value_or(executorResultCode_);
    IAM_LOGD("schedule result = %{public}d", result);
    callback->OnScheduleStoped(result, scheduleResult_);
    ClearScheduleCallback();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
