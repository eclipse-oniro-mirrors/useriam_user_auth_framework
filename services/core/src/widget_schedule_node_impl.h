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

#ifndef IAM_WIDGET_SCHEDULE_NODE_IMPL_H
#define IAM_WIDGET_SCHEDULE_NODE_IMPL_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <set>

#include "iam_hitrace_helper.h"

#include "finite_state_machine.h"
#include "resource_node.h"
#include "widget_schedule_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class WidgetScheduleNodeImpl final : public WidgetScheduleNode,
                               public std::enable_shared_from_this<WidgetScheduleNodeImpl>,
                               public NoCopyable {
public:
    WidgetScheduleNodeImpl();
    ~WidgetScheduleNodeImpl() override = default;
    bool StartSchedule() override;
    bool StartDirectAuth() override;
    bool StopSchedule() override;
    bool StartAuthList(const std::vector<AuthType> &authTypeList, bool endAfterFirstFail,
        AuthIntent authIntent) override;
    bool StopAuthList(const std::vector<AuthType> &authTypeList) override;
    bool SuccessAuth(AuthType authType) override;
    bool FailAuth(AuthType authType) override;
    bool NaviPinAuth() override;
    bool WidgetParaInvalid() override;
    bool WidgetReload(uint32_t orientation, uint32_t needRotate, uint32_t alreadyLoad,
        AuthType &rotateAuthType) override;
    void SetCallback(std::shared_ptr<WidgetScheduleNodeCallback> callback) override;
    void SendAuthTipInfo(const std::vector<AuthType> &authTypeList, int32_t tipCode) override;
    bool ClearSchedule() override;
    bool GetRemoteAuthParam() override;

protected:
    void OnStartSchedule(FiniteStateMachine &machine, uint32_t event);
    void OnStopSchedule(FiniteStateMachine &machine, uint32_t event);
    void OnStartDirectAuth(FiniteStateMachine &machine, uint32_t event);
    void OnStartAuth(FiniteStateMachine &machine, uint32_t event);
    void OnStopAuthList(FiniteStateMachine &machine, uint32_t event);
    void OnSuccessAuth(FiniteStateMachine &machine, uint32_t event);
    void OnNaviPinAuth(FiniteStateMachine &machine, uint32_t event);
    void OnWidgetParaInvalid(FiniteStateMachine &machine, uint32_t event);
    void OnWidgetReload(FiniteStateMachine &machine, uint32_t event);
    void OnWidgetReloadInit(FiniteStateMachine &machine, uint32_t event);
    void OnFailAuth(FiniteStateMachine &machine, uint32_t event);
    void OnWidgetRelease(FiniteStateMachine &machine, uint32_t event);
    void OnGetRemoteAuthParam(FiniteStateMachine &machine, uint32_t event);

private:
    std::shared_ptr<FiniteStateMachine> MakeFiniteStateMachine();
    void BuildInitStateTransitions(std::shared_ptr<FiniteStateMachine::Builder> &builder);
    void BuildWaitingStateTransitions(std::shared_ptr<FiniteStateMachine::Builder> &builder);
    void BuildAuthRunningStateTransitions(std::shared_ptr<FiniteStateMachine::Builder> &builder);
    void BuildReloadWaitingStateTransitions(std::shared_ptr<FiniteStateMachine::Builder> &builder);
    void BuildParamWaitingStateTransitions(std::shared_ptr<FiniteStateMachine::Builder> &builder);
    void BuildAuthFinishedStateTransitions(std::shared_ptr<FiniteStateMachine::Builder> &builder);
    bool TryKickMachine(Event event);

private:
    std::shared_ptr<ThreadHandler> threadHandler_ {nullptr};
    std::shared_ptr<FiniteStateMachine> machine_ {nullptr};
    std::mutex mutex_;
    std::shared_ptr<IamHitraceHelper> iamHitraceHelper_ {nullptr};
    std::weak_ptr<WidgetScheduleNodeCallback> callback_;
    AuthType successAuthType_ {0};
    AuthType failAuthType_ {0};
    std::vector<AuthType> startAuthTypeList_;
    bool endAfterFirstFail_ {false};
    std::vector<AuthType> stopAuthTypeList_;
    std::set<AuthType> runningAuthTypeSet_;
    uint32_t orientation_ {0};
    uint32_t needRotate_ {0};
    uint32_t alreadyLoad_ {0};
    AuthType rotateAuthType_ {0};
    AuthIntent authIntent_ {AuthIntent::DEFAULT};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_WIDGET_SCHEDULE_NODE_IMPL_H
