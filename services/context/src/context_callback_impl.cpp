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
#include "context_callback_impl.h"

#include <sstream>

#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_mem.h"
#include "iam_ptr.h"
#include "nlohmann/json.hpp"

#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
ContextCallbackImpl::ContextCallbackImpl(sptr<IamCallbackInterface> iamCallback, OperationType operationType)
    : iamCallback_(iamCallback)
{
    metaData_.operationType = operationType;
    metaData_.startTime = std::chrono::steady_clock::now();
    std::ostringstream ss;
    ss << "IDM(operation:" << operationType << ")";
    iamHitraceHelper_ = Common::MakeShared<IamHitraceHelper>(ss.str());
}

void ContextCallbackImpl::OnAcquireInfo(ExecutorRole src, int32_t moduleType,
    const std::vector<uint8_t> &acquireMsg)
{
    if (iamCallback_ == nullptr) {
        IAM_LOGE("iam callback is nullptr");
        return;
    }
    int32_t acquireInfo;
    Attributes attr(acquireMsg);
    bool getAcquireInfoRet = attr.GetInt32Value(Attributes::ATTR_TIP_INFO, acquireInfo);
    IF_FALSE_LOGE_AND_RETURN(getAcquireInfoRet);

    std::vector<uint8_t> extraInfo;
    bool getExtraInfoRet = attr.GetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, extraInfo);
    if (getExtraInfoRet) {
        ProcessAuthResult(acquireInfo, extraInfo);
    }

    iamCallback_->OnAcquireInfo(moduleType, acquireInfo, attr);
}

void ContextCallbackImpl::ProcessAuthResult(int32_t tip, const std::vector<uint8_t> &extraInfo)
{
    if (tip != USER_AUTH_TIP_SINGLE_AUTH_RESULT) {
        return;
    }
    if (extraInfo.empty()) {
        return;
    }
    std::string tipJson(reinterpret_cast<const char *>(extraInfo.data()), extraInfo.size());
    if (!nlohmann::json::accept(tipJson)) {
        IAM_LOGE("invalid format");
        return;
    }
    IAM_LOGI("tipJson:%{public}s", tipJson.c_str());
    auto root = nlohmann::json::parse(tipJson.c_str());
    if (root.is_null() || root.is_discarded()) {
        IAM_LOGE("root is null");
        return;
    }
    const std::string tipJsonKeyAuthResult = "authResult";
    int32_t authResult = 0;
    if (root.find(tipJsonKeyAuthResult) == root.end() || !(root[tipJsonKeyAuthResult].is_number())) {
        IAM_LOGE("authResult is null or is not number");
        return;
    }
    root.at(tipJsonKeyAuthResult).get_to(authResult);
    if (authResult == SUCCESS) {
        IAM_LOGI("authResult is success");
        return;
    }
    metaData_.operationResult = authResult;
    metaData_.endTime = std::chrono::steady_clock::now();
    IAM_LOGI("fingerprint single auth result, tip: %{public}d, result: %{public}d", tip, authResult);
    ContextCallbackNotifyListener::GetInstance().Process(metaData_, TRACE_FLAG_NO_NEED_BEHAVIOR);
    return;
}

void ContextCallbackImpl::OnResult(int32_t resultCode, const Attributes &finalResult)
{
    int32_t remainTime;
    int32_t freezingTime;
    metaData_.operationResult = resultCode;
    if (finalResult.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, remainTime)) {
        metaData_.remainTime = remainTime;
    }
    if (finalResult.GetInt32Value(Attributes::ATTR_FREEZING_TIME, freezingTime)) {
        metaData_.freezingTime = freezingTime;
    }
    metaData_.endTime = std::chrono::steady_clock::now();

    if (iamCallback_ != nullptr) {
        iamCallback_->OnResult(resultCode, finalResult);
    }

    ContextCallbackNotifyListener::GetInstance().Process(metaData_, TRACE_FLAG_DEFAULT);
    if (stopCallback_ != nullptr) {
        stopCallback_();
    }
}

void ContextCallbackImpl::SetTraceUserId(int32_t userId)
{
    metaData_.userId = userId;
}

void ContextCallbackImpl::SetTraceRemainTime(int32_t remainTime)
{
    metaData_.remainTime = remainTime;
}

void ContextCallbackImpl::SetTraceCallerName(const std::string &callerName)
{
    metaData_.callerName = callerName;
}

void ContextCallbackImpl::SetTraceRequestContextId(uint64_t requestContextId)
{
    metaData_.requestContextId = requestContextId;
}

void ContextCallbackImpl::SetTraceAuthContextId(uint64_t authContextId)
{
    metaData_.authContextId = authContextId;
}

void ContextCallbackImpl::SetTraceFreezingTime(int32_t freezingTime)
{
    metaData_.freezingTime = freezingTime;
}

void ContextCallbackImpl::SetTraceSdkVersion(int32_t version)
{
    metaData_.sdkVersion = version;
}

void ContextCallbackImpl::SetTraceAuthType(int32_t authType)
{
    metaData_.authType = authType;
}

void ContextCallbackImpl::SetTraceAuthWidgetType(uint32_t authWidgetType)
{
    metaData_.authWidgetType = authWidgetType;
}

void ContextCallbackImpl::SetTraceAuthTrustLevel(AuthTrustLevel atl)
{
    metaData_.atl = atl;
}

void ContextCallbackImpl::SetTraceCallerType(int32_t callerType)
{
    metaData_.callerType = callerType;
}

void ContextCallbackImpl::SetTraceReuseUnlockResultMode(uint32_t reuseUnlockResultMode)
{
    metaData_.reuseUnlockResultMode = reuseUnlockResultMode;
}

void ContextCallbackImpl::SetTraceReuseUnlockResultDuration(uint64_t reuseUnlockResultDuration)
{
    metaData_.reuseUnlockResultDuration = reuseUnlockResultDuration;
}

void ContextCallbackImpl::SetCleaner(Context::ContextStopCallback callback)
{
    stopCallback_ = callback;
}

sptr<IamCallbackInterface> ContextCallbackImpl::GetIamCallback()
{
    return iamCallback_;
}

std::string ContextCallbackImpl::GetCallerName()
{
    if (metaData_.callerName.has_value()) {
        return metaData_.callerName.value();
    }
    return "";
}

ContextCallbackNotifyListener &ContextCallbackNotifyListener::GetInstance()
{
    static ContextCallbackNotifyListener contextCallbackNotifyListener;
    return contextCallbackNotifyListener;
}

void ContextCallbackNotifyListener::AddNotifier(const Notify &notify)
{
    notifierList_.emplace_back(notify);
}

void ContextCallbackNotifyListener::Process(const MetaData &metaData, TraceFlag flag)
{
    for (const auto &notify : notifierList_) {
        if (notify != nullptr) {
            notify(metaData, flag);
        }
    }
}

std::shared_ptr<ContextCallback> ContextCallback::NewInstance(sptr<IamCallbackInterface> iamCallback,
    OperationType operationType)
{
    if (iamCallback == nullptr) {
        IAM_LOGE("iam callback is nullptr, parameter is invalid");
        return nullptr;
    }
    return UserIam::Common::MakeShared<ContextCallbackImpl>(iamCallback, operationType);
}

class IamDummyCallback : public IamCallbackInterface, public NoCopyable {
public:
    explicit IamDummyCallback() = default;
    ~IamDummyCallback() override = default;
    void OnResult(int32_t result, const Attributes &extraInfo) override
    {
        static_cast<void>(result);
        static_cast<void>(extraInfo);
    }
    void OnAcquireInfo(int32_t module, int32_t acquireInfo, const Attributes &extraInfo) override
    {
        static_cast<void>(module);
        static_cast<void>(acquireInfo);
        static_cast<void>(extraInfo);
    }
    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }
};

std::shared_ptr<ContextCallback> ContextCallback::NewDummyInstance(OperationType operationType)
{
    sptr<IamCallbackInterface> iamDummyCallback(new (std::nothrow) IamDummyCallback());
    if (iamDummyCallback == nullptr) {
        IAM_LOGE("iamDummyCallback is nullptr");
        return nullptr;
    }
    return UserIam::Common::MakeShared<ContextCallbackImpl>(iamDummyCallback, operationType);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS