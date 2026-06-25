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

#ifndef MOCK_IAM_WIDGET_CONTEXT_H
#define MOCK_IAM_WIDGET_CONTEXT_H

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <list>
#include <vector>

#include "auth_common.h"
#include "extension_manager_client.h"
#include "authentication_impl.h"
#include "base_context.h"
#include "context.h"
#include "context_appstate_observer.h"
#include "context_death_recipient.h"
#include "context_factory.h"
#include "in_process_call_wrapper.h"
#include "iiam_callback.h"
#include "imodal_callback.h"
#include "iremote_auth_callback.h"
#include "nocopyable.h"
#include "widget_json.h"
#include "widget_schedule_node.h"
#include "ui_extension_ability_connection.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS::AppExecFwk;
class WidgetContext : public WidgetScheduleNodeCallback,
                      public Context,
                      public std::enable_shared_from_this<WidgetContext>,
                      public ContextDeathRecipientManager,
                      public ContextAppStateObserverManager,
                      public NoCopyable {
public:
    WidgetContext(uint64_t contextId, const ContextFactory::AuthWidgetContextPara &para,
        std::shared_ptr<ContextCallback> callback, const sptr<IModalCallback> &modalCallback,
        const sptr<IRemoteAuthCallback> &remoteAuthCallback);
    ~WidgetContext() override;

    // Context API
    bool Start() override;
    bool Stop() override;
    uint64_t GetContextId() const override;
    ContextType GetContextType() const override;
    std::shared_ptr<ScheduleNode> GetScheduleNode(uint64_t scheduleId) const override;
    uint32_t GetTokenId() const override;
    int32_t GetLatestError() const override;
    int32_t GetUserId() const override;
    int32_t GetAuthType() const override;
    std::string GetCallerName() const override;
    void SetRemoteAuthParam(const WidgetParamInner &widgetParam, const sptr<IModalCallback> &modalCallback) override;

    // WidgetScheduleNodeCallback API
    bool LaunchWidget() override;
    void ExecuteAuthList(const std::set<AuthType> &authTypeList, bool endAfterFirstFail,
        AuthIntent authIntent) override;
    void EndAuthAsCancel() override;
    void EndAuthAsNaviPin() override;
    void EndAuthAsWidgetParaInvalid() override;
    void StopAuthList(const std::vector<AuthType> &authTypeList) override;
    void SuccessAuth(AuthType authType) override;
    void FailAuth(AuthType authType) override;
    bool AuthWidgetReload(uint32_t orientation, uint32_t needRotate, uint32_t alreadyLoad,
        AuthType &rotateAuthType) override;
    void AuthWidgetReloadInit() override;
    bool GetRemoteAuthParam() override;

    void AuthResult(int32_t resultCode, int32_t authType, const Attributes &finalResult);
    void AuthTipInfo(int32_t tipInfo, int32_t authType, const Attributes &extraInfo);
    void ClearSchedule() override;
    void SendAuthTipInfo(int32_t authType, int32_t tipInfo) override;

private:
    struct WidgetRotatePara {
        bool isReload {false};
        uint32_t orientation {0};
        uint32_t needRotate {0};
        uint32_t alreadyLoad {0};
        AuthType rotateAuthType {0};
    };
    void SetLatestError(int32_t error) override;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MOCK_IAM_WIDGET_CONTEXT_H