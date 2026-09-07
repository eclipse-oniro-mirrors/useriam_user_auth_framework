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

#ifndef IAM_CONTEXT_CALLBACK_H
#define IAM_CONTEXT_CALLBACK_H

#include <cstdint>
#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include "context.h"
#include "iam_defines.h"
#include "iiam_callback.h"
#include "user_auth_common_defines.h"
#include "iam_framework_stages.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ContextCallbackNotifyListener {
public:
    struct MetaData {
        OperationType operationType;
        int32_t operationResult = -1;
        std::optional<int32_t> userId;
        std::optional<int32_t> remainTime;
        std::optional<int32_t> freezingTime;
        std::optional<int32_t> sdkVersion;
        std::optional<uint64_t> requestContextId;
        std::optional<uint64_t> authContextId;
        std::optional<AuthTrustLevel> atl;
        std::optional<int32_t> authType;
        std::optional<uint32_t> authWidgetType;
        std::optional<std::string> callerName;
        std::optional<int32_t> callerType;
        std::chrono::time_point<std::chrono::steady_clock> startTime;
        std::chrono::time_point<std::chrono::steady_clock> endTime;
        std::optional<uint32_t> reuseUnlockResultMode;
        std::optional<uint64_t> reuseUnlockResultDuration;
        std::optional<bool> isRemoteAuth;
        std::optional<std::string> remoteUdid;
        std::optional<std::string> localUdid;
        std::optional<std::string> connectionName;
        std::optional<std::string> authFinishReason;
        std::optional<bool> isBackgroundApplication;
        std::optional<bool> isWidgetAuth;
        std::optional<uint32_t> totalTime;
        std::optional<uint32_t> localTime;
        std::optional<uint32_t> authSuccTipTime;
        std::optional<std::string> extraInfo;
    };
    using Notify = std::function<void(const MetaData &metaData, TraceFlag flag)>;
    static ContextCallbackNotifyListener &GetInstance();
    void AddNotifier(const Notify &notify);
    void Process(const MetaData &metaData, TraceFlag flag);

private:
    std::vector<Notify> notifierList_;
};

class ContextCallback {
public:
    static std::shared_ptr<ContextCallback> NewInstance(sptr<IIamCallback> iamCallback,
        OperationType operationType);
    static std::shared_ptr<ContextCallback> NewDummyInstance(OperationType operationType);
    virtual ~ContextCallback() = default;
    virtual void OnResult(int32_t resultCode, const Attributes &finalResult) = 0;
    virtual void OnAcquireInfo(ExecutorRole src, int32_t moduleType, const std::vector<uint8_t> &acquireMsg) = 0;
    virtual void SetTraceCallerName(const std::string &callerName) = 0;
    virtual void SetTraceRequestContextId(uint64_t requestContextId) = 0;
    virtual void SetTraceAuthContextId(uint64_t authContextId) = 0;
    virtual void SetTraceUserId(int32_t userId) = 0;
    virtual void SetTraceRemainTime(int32_t remainTime) = 0;
    virtual void SetTraceFreezingTime(int32_t freezingTime) = 0;
    virtual void SetTraceSdkVersion(int32_t version) = 0;
    virtual void SetTraceAuthType(int32_t authType) = 0;
    virtual void SetTraceAuthWidgetType(uint32_t authWidgetType) = 0;
    virtual void SetTraceAuthTrustLevel(AuthTrustLevel atl) = 0;
    virtual void SetTraceReuseUnlockResultMode(uint32_t reuseUnlockResultMode) = 0;
    virtual void SetTraceReuseUnlockResultDuration(uint64_t reuseUnlockResultDuration) = 0;
    virtual void SetCleaner(Context::ContextStopCallback callback) = 0;
    virtual void SetTraceCallerType(int32_t callerType) = 0;
    virtual void SetTraceIsRemoteAuth(bool isRemoteAuth) = 0;
    virtual void SetTraceLocalUdid(const std::string &localUdid) = 0;
    virtual void SetTraceRemoteUdid(const std::string &remoteUdid) = 0;
    virtual void SetTraceConnectionName(const std::string &connectionName) = 0;
    virtual void SetTraceAuthFinishReason(const std::string &authFinishReason) = 0;
    virtual void SetTraceIsBackgroundApplication(bool isBackgroundApplication) = 0;
    virtual void SetTraceIsWidgetAuth(bool isWidgetAuth) = 0;
    virtual int32_t ParseAuthTipInfo(int32_t tip, const std::vector<uint8_t> &extraInfo,
        int32_t &authResult, int32_t &freezingTime) = 0;
    virtual void ProcessAuthResult(int32_t tip, const std::vector<uint8_t> &extraInfo) = 0;
    virtual sptr<IIamCallback> GetIamCallback() = 0;
    virtual std::string GetCallerName() = 0;

    virtual void Mark(StageId id) = 0;
    virtual void EnterWait(StageId id) = 0;
    virtual void ExitWait(StageId id) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_CONTEXT_CALLBACK_H