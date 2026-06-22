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

#include "framework_executor_callback.h"

#include <mutex>
#include <sstream>

#include "abandon_command.h"
#include "auth_command.h"
#include "collect_command.h"
#include "custom_command.h"
#include "enroll_command.h"
#include "hisysevent_adapter.h"
#include "iam_check.h"
#include "iam_defines.h"
#include "iam_hitrace_helper.h"
#include "iam_logger.h"
#include "iam_mem.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "identify_command.h"

#define LOG_TAG "USER_AUTH_EXECUTOR"
#define LOG_FILE_ID LOG_FILE_FRAMEWORK_EXECUTOR_CALLBACK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
const std::map<Attributes::AttributeKey, std::function<bool(std::shared_ptr<Attributes>, const Property &)>>
    FrameworkExecutorCallback::propertyFillers_ = {
        {Attributes::ATTR_PIN_SUB_TYPE,
            [](std::shared_ptr<Attributes> vals, const Property &prop) {
                return vals->SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, prop.authSubType);
            }},
        {Attributes::ATTR_FREEZING_TIME,
            [](std::shared_ptr<Attributes> vals, const Property &prop) {
                return vals->SetInt32Value(Attributes::ATTR_FREEZING_TIME, prop.lockoutDuration);
            }},
        {Attributes::ATTR_REMAIN_TIMES,
            [](std::shared_ptr<Attributes> vals, const Property &prop) {
                return vals->SetInt32Value(Attributes::ATTR_REMAIN_TIMES, prop.remainAttempts);
            }},
        {Attributes::ATTR_ENROLL_PROGRESS,
            [](std::shared_ptr<Attributes> vals, const Property &prop) {
                return vals->SetStringValue(Attributes::ATTR_ENROLL_PROGRESS, prop.enrollmentProgress);
            }},
        {Attributes::ATTR_SENSOR_INFO,
            [](std::shared_ptr<Attributes> vals, const Property &prop) {
                return vals->SetStringValue(Attributes::ATTR_SENSOR_INFO, prop.sensorInfo);
            }},
        {Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION,
            [](std::shared_ptr<Attributes> vals, const Property &prop) {
                return vals->SetInt32Value(Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION, prop.nextFailLockoutDuration);
            }},
        {Attributes::ATTR_CREDENTIAL_LENGTH,
            [](std::shared_ptr<Attributes> vals, const Property &prop) {
                if (prop.credentialLength == 0) {
                    return true;
                }
                return vals->SetUint32Value(Attributes::ATTR_CREDENTIAL_LENGTH, prop.credentialLength);
            }},
        {Attributes::ATTR_CAMERA_STATUS,
            [](std::shared_ptr<Attributes> vals, const Property &prop) {
                return vals->SetUint32Value(Attributes::ATTR_CAMERA_STATUS, prop.cameraStatus);
            }},
};

FrameworkExecutorCallback::FrameworkExecutorCallback(std::weak_ptr<Executor> executor) : executor_(executor)
{
    uint32_t callbackId = GenerateExecutorCallbackId();
    std::ostringstream ss;
    ss << "ExecutorCallback(Id:" << callbackId << ")";
    description_ = ss.str();
}

int32_t FrameworkExecutorCallback::OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
    const Attributes &commandAttrs)
{
    auto pk(publicKey);

    return OnBeginExecuteInner(scheduleId, pk, commandAttrs);
}

ResultCode FrameworkExecutorCallback::OnBeginExecuteInner(uint64_t scheduleId, std::vector<uint8_t> &publicKey,
    const Attributes &commandAttrs)
{
    static_cast<void>(publicKey);
    int32_t commandId = 0;
    bool getScheduleModeRet =
        commandAttrs.GetInt32Value(Attributes::ATTR_SCHEDULE_MODE, commandId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getScheduleModeRet == true, ResultCode::GENERAL_ERROR);

    IAM_LOGD("%{public}s start process cmd %{public}u", GetDescription(), commandId);
    ResultCode ret = ResultCode::GENERAL_ERROR;
    switch (commandId) {
        case ENROLL:
            ret = ProcessEnrollCommand(scheduleId, commandAttrs);
            break;
        case AUTH:
            ret = ProcessAuthCommand(scheduleId, commandAttrs);
            break;
        case IDENTIFY:
            ret = ProcessIdentifyCommand(scheduleId, commandAttrs);
            break;
        case ABANDON:
            ret = ProcessAbandonCommand(scheduleId, commandAttrs);
            break;
        default:
            IAM_LOGE("command id %{public}u is not supported", commandId);
    }

    IAM_LOGD("command id = %{public}u ret = %{public}d", commandId, ret);
    return ret;
}

int32_t FrameworkExecutorCallback::OnEndExecute(uint64_t scheduleId, const Attributes &commandAttrs)
{
    return OnEndExecuteInner(scheduleId, commandAttrs);
}

ResultCode FrameworkExecutorCallback::OnEndExecuteInner(uint64_t scheduleId, const Attributes &consumerAttr)
{
    ResultCode ret = ProcessCancelCommand(scheduleId);
    IAM_LOGI("%{public}s cancel scheduleId %{public}s ret %{public}d", GetDescription(),
        GET_MASKED_STRING(scheduleId).c_str(), ret);
    return ret;
}

void FrameworkExecutorCallback::OnMessengerReady(const std::shared_ptr<ExecutorMessenger> &messenger,
    const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIdList)
{
    IAM_LOGD("%{public}s start", GetDescription());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("executor has been released, process failed");
        return;
    }
    auto hdi = executor->GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN(hdi != nullptr);
    executorMessenger_ = messenger;
    std::vector<uint8_t> extraInfo;
    hdi->OnRegisterFinish(templateIdList, publicKey, extraInfo);
}

int32_t FrameworkExecutorCallback::OnSetProperty(const Attributes &properties)
{
    return OnSetPropertyInner(properties);
}

ResultCode FrameworkExecutorCallback::OnSetPropertyInner(const Attributes &properties)
{
    uint32_t commandId = 0;
    bool getAuthPropertyModeRet =
        properties.GetUint32Value(Attributes::ATTR_PROPERTY_MODE, commandId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAuthPropertyModeRet == true, ResultCode::GENERAL_ERROR);
    IAM_LOGD("%{public}s start process cmd %{public}u", GetDescription(), commandId);
    ResultCode ret;
    if (commandId == PROPERTY_MODE_DEL) {
        ret = ProcessDeleteTemplateCommand(properties);
    } else if (commandId == PROPERTY_MODE_SET_CACHED_TEMPLATES) {
        ret = ProcessSetCachedTemplates(properties);
    } else if (commandId == PROPERTY_MODE_NOTIFY_COLLECTOR_READY) {
        ret = ProcessNotifyExecutorReady(properties);
    } else {
        ret = ProcessCustomCommand(properties);
    }
    IAM_LOGI("command id = %{public}u ret = %{public}d", commandId, ret);
    return ret;
}

int32_t FrameworkExecutorCallback::OnGetProperty(const Attributes &conditions, Attributes &results)
{
    auto cond = Common::MakeShared<Attributes>(conditions.Serialize());
    auto values = Common::MakeShared<Attributes>(results.Serialize());
    auto ret = OnGetPropertyInner(cond, values);
    if (values) {
        results = std::move(*values);
    }
    return ret;
}

int32_t FrameworkExecutorCallback::OnSendData(uint64_t scheduleId, const Attributes &data)
{
    int32_t srcRole = 0;
    bool getDestRoleRet = data.GetInt32Value(Attributes::ATTR_SRC_ROLE, srcRole);
    IF_FALSE_LOGE_AND_RETURN_VAL(getDestRoleRet == true, ResultCode::GENERAL_ERROR);
    std::vector<uint8_t> extraInfo;
    bool getExtraInfoRet = data.GetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, extraInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(getExtraInfoRet == true, ResultCode::GENERAL_ERROR);

    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("executor has been released, process failed");
        return ResultCode::GENERAL_ERROR;
    }
    auto hdi = executor->GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);
    return hdi->SendMessage(scheduleId, srcRole, extraInfo);
}

ResultCode FrameworkExecutorCallback::OnGetPropertyInner(std::shared_ptr<Attributes> conditions,
    std::shared_ptr<Attributes> values)
{
    IAM_LOGD("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(conditions != nullptr, ResultCode::GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN_VAL(values != nullptr, ResultCode::GENERAL_ERROR);
    uint32_t commandId = 0;
    bool getAuthPropertyModeRet =
        conditions->GetUint32Value(Attributes::ATTR_PROPERTY_MODE, commandId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAuthPropertyModeRet == true, ResultCode::GENERAL_ERROR);
    if (commandId != PROPERTY_MODE_GET) {
        IAM_LOGE("command id not recognised");
        return ResultCode::GENERAL_ERROR;
    }

    ResultCode ret = ProcessGetPropertyCommand(conditions, values);
    IAM_LOGD("command id = %{public}u ret = %{public}d", commandId, ret);
    return ret;
}

ResultCode FrameworkExecutorCallback::ProcessEnrollCommand(uint64_t scheduleId, const Attributes &properties)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto command = Common::MakeShared<EnrollCommand>(executor_, scheduleId, properties, executorMessenger_);
    IF_FALSE_LOGE_AND_RETURN_VAL(command != nullptr, ResultCode::GENERAL_ERROR);
    return command->StartProcess();
}

ResultCode FrameworkExecutorCallback::ProcessAuthCommand(uint64_t scheduleId, const Attributes &properties)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("executor has been released, process failed");
        return ResultCode::GENERAL_ERROR;
    }

    std::shared_ptr<AsyncCommandBase> command = nullptr;
    if (executor->GetExecutorRole() == COLLECTOR) {
        command = Common::MakeShared<CollectCommand>(executor_, scheduleId, properties, executorMessenger_);
    } else {
        command = Common::MakeShared<AuthCommand>(executor_, scheduleId, properties, executorMessenger_);
    }
    IF_FALSE_LOGE_AND_RETURN_VAL(command != nullptr, ResultCode::GENERAL_ERROR);
    return command->StartProcess();
}

ResultCode FrameworkExecutorCallback::ProcessIdentifyCommand(uint64_t scheduleId, const Attributes &properties)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto command = Common::MakeShared<IdentifyCommand>(executor_, scheduleId, properties, executorMessenger_);
    IF_FALSE_LOGE_AND_RETURN_VAL(command != nullptr, ResultCode::GENERAL_ERROR);
    return command->StartProcess();
}

ResultCode FrameworkExecutorCallback::ProcessCancelCommand(uint64_t scheduleId)
{
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("executor has been released, process failed");
        return ResultCode::GENERAL_ERROR;
    }
    auto hdi = executor->GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);
    return hdi->Cancel(scheduleId);
}

ResultCode FrameworkExecutorCallback::ProcessDeleteTemplateCommand(const Attributes &properties)
{
    IAM_LOGI("start");
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("executor has been released, process failed");
        return ResultCode::GENERAL_ERROR;
    }
    auto hdi = executor->GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);
    uint64_t templateId = 0;
    bool getAuthTemplateIdRet = properties.GetUint64Value(Attributes::ATTR_TEMPLATE_ID, templateId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAuthTemplateIdRet == true, ResultCode::GENERAL_ERROR);
    std::vector<uint64_t> templateIdList;

    templateIdList.push_back(templateId);
    IamHitraceHelper traceHelper("hdi Delete");
    ResultCode ret = hdi->Delete(templateIdList);
    if (ret == ResultCode::SUCCESS) {
        TemplateChangeTrace info = {};
        info.changeType = TRACE_DELETE_CREDENTIAL;
        std::string templateChangeReason = "";
        properties.GetStringValue(Attributes::ATTR_TEMPLATE_CHANGE_REASON, templateChangeReason);
        info.reason = templateChangeReason;
        info.executorType = executor->GetAuthType();
        UserIam::UserAuth::ReportSecurityTemplateChange(info);
    }
    HILOG_COMM_INFO("fwk callback proc delete template, templateId: %{public}s",
        Common::GetMaskedString(templateId).c_str());
    return ret;
}

ResultCode FrameworkExecutorCallback::ProcessSetCachedTemplates(const Attributes &properties)
{
    IAM_LOGI("start");
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("executor has been released, process failed");
        return ResultCode::GENERAL_ERROR;
    }
    auto hdi = executor->GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);

    std::vector<uint64_t> templateIdList;
    bool getTemplateIdListRet = properties.GetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIdList);
    IF_FALSE_LOGE_AND_RETURN_VAL(getTemplateIdListRet == true, ResultCode::GENERAL_ERROR);

    return hdi->SetCachedTemplates(templateIdList);
}

ResultCode FrameworkExecutorCallback::ProcessNotifyExecutorReady(const Attributes &properties)
{
    IAM_LOGI("start");
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("executor has been released, process failed");
        return ResultCode::GENERAL_ERROR;
    }

    auto hdi = executor->GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);

    uint64_t scheduleId;
    bool getScheduleIdRet = properties.GetUint64Value(Attributes::ATTR_SCHEDULE_ID, scheduleId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getScheduleIdRet == true, ResultCode::GENERAL_ERROR);

    return hdi->NotifyCollectorReady(scheduleId);
}

ResultCode FrameworkExecutorCallback::ProcessCustomCommand(const Attributes &properties)
{
    auto command = Common::MakeShared<CustomCommand>(executor_, properties);
    IF_FALSE_LOGE_AND_RETURN_VAL(command != nullptr, ResultCode::GENERAL_ERROR);
    ResultCode ret = command->StartProcess();
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("start process command fail ret = %{public}d", ret);
        return ret;
    }

    return command->GetResult();
}

ResultCode FrameworkExecutorCallback::ProcessGetPropertyCommand(std::shared_ptr<Attributes> conditions,
    std::shared_ptr<Attributes> values)
{
    IAM_LOGD("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(conditions != nullptr, ResultCode::GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN_VAL(values != nullptr, ResultCode::GENERAL_ERROR);
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("executor has been released, process failed");
        return ResultCode::GENERAL_ERROR;
    }
    auto hdi = executor->GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);

    std::vector<uint64_t> templateIdList;
    bool getTemplateIdListRet = conditions->GetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIdList);
    IF_FALSE_LOGE_AND_RETURN_VAL(getTemplateIdListRet == true, ResultCode::GENERAL_ERROR);

    std::vector<uint32_t> uint32KeyList;
    bool getKeyListRet = conditions->GetUint32ArrayValue(Attributes::ATTR_KEY_LIST, uint32KeyList);
    IF_FALSE_LOGE_AND_RETURN_VAL(getKeyListRet == true, ResultCode::GENERAL_ERROR);

    std::vector<Attributes::AttributeKey> keyList;
    keyList.reserve(uint32KeyList.size());
    for (auto &uint32Key : uint32KeyList) {
        keyList.push_back(static_cast<Attributes::AttributeKey>(uint32Key));
    }

    Property property = {};

    ResultCode getPropertyRet = hdi->GetProperty(templateIdList, keyList, property);
    IF_FALSE_LOGE_AND_RETURN_VAL(getPropertyRet == SUCCESS, ResultCode::GENERAL_ERROR);

    ResultCode fillAttributeRet = FillPropertyToAttribute(keyList, property, values);
    IF_FALSE_LOGE_AND_RETURN_VAL(fillAttributeRet == SUCCESS, ResultCode::GENERAL_ERROR);

    return ResultCode::SUCCESS;
}

ResultCode FrameworkExecutorCallback::ProcessAbandonCommand(uint64_t scheduleId, const Attributes &properties)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto command = Common::MakeShared<AbandonCommand>(executor_, scheduleId, properties, executorMessenger_);
    IF_FALSE_LOGE_AND_RETURN_VAL(command != nullptr, ResultCode::GENERAL_ERROR);
    return command->StartProcess();
}

ResultCode FrameworkExecutorCallback::FillPropertyToAttribute(const std::vector<Attributes::AttributeKey> &keyList,
    const Property property, std::shared_ptr<Attributes> values)
{
    for (auto &key : keyList) {
        auto it = propertyFillers_.find(key);
        if (it == propertyFillers_.end()) {
            IAM_LOGE("key %{public}d is not recognized", key);
            return ResultCode::GENERAL_ERROR;
        }
        auto ret = it->second(values, property);
        IF_FALSE_LOGE_AND_RETURN_VAL(ret, ResultCode::GENERAL_ERROR);
    }
    return ResultCode::SUCCESS;
}

uint32_t FrameworkExecutorCallback::GenerateExecutorCallbackId()
{
    static std::mutex mutex;
    static uint32_t callbackId = 0;
    std::lock_guard<std::mutex> guard(mutex);
    // callbackId is only used in log, uint32 overflow or duplicate is ok
    ++callbackId;
    return callbackId;
}

const char *FrameworkExecutorCallback::GetDescription()
{
    return description_.c_str();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
