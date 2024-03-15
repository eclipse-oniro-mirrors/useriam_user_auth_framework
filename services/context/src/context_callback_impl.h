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

#ifndef CONTEXT_CALLBACK_IMPL_H
#define CONTEXT_CALLBACK_IMPL_H

#include "iam_hitrace_helper.h"
#include "iam_defines.h"

#include "context_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ContextCallbackImpl : public ContextCallback, public NoCopyable {
public:
    explicit ContextCallbackImpl(sptr<IamCallbackInterface> iamCallback, OperationType operationType);
    ~ContextCallbackImpl() override = default;
    void OnResult(int32_t resultCode, const Attributes &finalResult) override;
    void OnAcquireInfo(ExecutorRole src, int32_t moduleType, const std::vector<uint8_t> &acquireMsg) override;
    void SetTraceCallerName(const std::string &callerName) override;
    void SetTraceRequestContextId(uint64_t requestContextId) override;
    void SetTraceAuthContextId(uint64_t authContextId) override;
    void SetTraceUserId(int32_t userId) override;
    void SetTraceRemainTime(int32_t remainTime) override;
    void SetTraceFreezingTime(int32_t freezingTime) override;
    void SetTraceSdkVersion(int32_t version) override;
    void SetTraceAuthType(int32_t authType) override;
    void SetTraceAuthWidgetType(uint32_t authWidgetType) override;
    void SetTraceAuthTrustLevel(AuthTrustLevel atl) override;
    void SetTraceReuseUnlockResultMode(uint32_t reuseUnlockResultMode) override;
    void SetTraceReuseUnlockResultDuration(uint64_t reuseUnlockResultDuration) override;
    void SetCleaner(Context::ContextStopCallback callback) override;
    void SetTraceCallerType(int32_t callerType) override;
    void ProcessAuthResult(int32_t tip, const std::vector<uint8_t> &extraInfo) override;
    sptr<IamCallbackInterface> GetIamCallback() override;
    std::string GetCallerName() override;

private:
    sptr<IamCallbackInterface> iamCallback_ {nullptr};
    Context::ContextStopCallback stopCallback_ {nullptr};
    ContextCallbackNotifyListener::MetaData metaData_;
    std::shared_ptr<IamHitraceHelper> iamHitraceHelper_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // CONTEXT_CALLBACK_IMPL_H