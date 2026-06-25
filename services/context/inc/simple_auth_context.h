/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef IAM_SIMPLE_AUTH_CONTEXT_H
#define IAM_SIMPLE_AUTH_CONTEXT_H

#include <cstdint>
#include <memory>

#include "authentication_impl.h"
#include "base_context.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
constexpr int32_t FIRST_LOCKOUT_DURATION_OF_PIN = 60 * 1000;
constexpr int32_t FIRST_LOCKOUT_DURATION_EXCEPT_PIN = 30 * 1000;

class SimpleAuthContext : public BaseContext {
public:
    SimpleAuthContext(uint64_t contextId, std::shared_ptr<Authentication> auth,
        std::shared_ptr<ContextCallback> callback, bool needSubscribeAppState);
    SimpleAuthContext(const std::string &type, uint64_t contextId, std::shared_ptr<Authentication> auth,
        std::shared_ptr<ContextCallback> callback);
    ~SimpleAuthContext() override = default;
    ContextType GetContextType() const override;
    uint32_t GetTokenId() const override;
    int32_t GetUserId() const override;
    int32_t GetAuthType() const override;
    std::string GetCallerName() const override;
    void SetRemoteAuthParam(const WidgetParamInner &widgetParam, const sptr<IModalCallback> &modalCallback) override;

protected:
    bool OnStart() override;
    void OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr) override;
    bool OnStop() override;

    std::shared_ptr<Authentication> auth_ = nullptr;

private:
    bool UpdateScheduleResult(const std::shared_ptr<Attributes> &scheduleResultAttr,
        Authentication::AuthResultInfo &resultInfo);
    void SendAuthExecutorMsg();
    void InvokeResultCallback(const Authentication::AuthResultInfo &resultInfo) const;
    ResultCode SetFreezingTimeAndRemainTimes(int32_t &freezingTime, int32_t &remainTimes);
    ResultCode GetPropertyForAuthResult(Authentication::AuthResultInfo &resultInfo);
    bool SetCredentialDigest(const Authentication::AuthResultInfo &resultInfo,
        Attributes &finalResult) const;
    std::optional<std::vector<uint64_t>> GetPropertyTemplateIds(
        Authentication::AuthResultInfo &resultInfo);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_SIMPLE_AUTH_CONTEXT_H