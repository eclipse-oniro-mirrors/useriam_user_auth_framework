/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef IAM_SUDO_AUTH_CONTEXT_H
#define IAM_SUDO_AUTH_CONTEXT_H

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>

#include "base_context.h"
#include "context_factory.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class SudoChildCallbackImpl;

class SudoAuthContext : public BaseContext {
public:
    SudoAuthContext(uint64_t contextId, const ContextFactory::SudoAuthContextPara &para,
        std::shared_ptr<ContextCallback> callback);
    ~SudoAuthContext() override = default;

    ContextType GetContextType() const override;
    uint32_t GetTokenId() const override;
    int32_t GetUserId() const override;
    int32_t GetAuthType() const override;
    std::vector<int32_t> GetAuthTypeList() const override;
    AuthIntent GetAuthIntent() const override;
    std::string GetCallerName() const override;
    bool CanStart(const std::vector<std::weak_ptr<Context>> &predecessors) const override;
    PreemptDecision GetPreemptDecision(const Context &newRequest) const override;
    static std::string ResolveWidgetTitle(const std::string &additionalInfo);

protected:
    bool OnStart() override;
    bool OnStop() override;
    void OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr) override;

#ifndef IAM_TEST_ENABLE
private:
#endif
    friend class SudoChildCallbackImpl;

    enum SudoPhase {
        PHASE_QUERY,
        PHASE_RUN,
        PHASE_END,
    };
    void EndWithLocked(const ContextFactory::AuthProfile &profile);
    void DispatchByProfile(const ContextFactory::AuthProfile &profile);
    virtual bool StartSilentChild(const ContextFactory::AuthProfile &profile);
    virtual bool StartWidgetChild(const ContextFactory::AuthProfile &profile);
    bool LaunchChild(const std::shared_ptr<Context> &child);
    void OnChildResult(int32_t resultCode, const Attributes &finalResult);
    void EndWithResult(int32_t resultCode, const Attributes &finalResult);
    std::shared_ptr<ContextCallback> BuildChildCallback();

    ContextFactory::SudoAuthContextPara para_ {};
    std::recursive_mutex sudoMutex_;
    std::atomic<bool> dialogActive_ {false};
    SudoPhase phase_ {PHASE_QUERY};
    std::optional<uint64_t> childContextId_ {};
    bool childIsWidget_ {false};
    bool stopping_ {false};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_SUDO_AUTH_CONTEXT_H
