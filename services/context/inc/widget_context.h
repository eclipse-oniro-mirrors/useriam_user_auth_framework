/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef IAM_WIDGET_CONTEXT_H
#define IAM_WIDGET_CONTEXT_H

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

protected:
    virtual bool OnStart();
    virtual void OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr);
    virtual bool OnStop();
    virtual bool BuildSchedule();

private:
    struct WidgetRotatePara {
        bool isReload {false};
        uint32_t orientation {0};
        uint32_t needRotate {0};
        uint32_t alreadyLoad {0};
        AuthType rotateAuthType {0};
    };
    void SetLatestError(int32_t error) override;
    std::shared_ptr<Context> BuildTask(const std::vector<uint8_t> &challenge,
        AuthType authType, AuthTrustLevel authTrustLevel, bool endAfterFirstFail, AuthIntent authIntent);
    bool ConnectExtension(const WidgetRotatePara &widgetRotatePara);
    int32_t ConnectExtensionAbility(const AAFwk::Want &want, const std::string commandStr);
    bool DisconnectExtension();
    void End(const ResultCode &resultCode);
    std::shared_ptr<ContextCallback> GetAuthContextCallback(AuthType authType, AuthTrustLevel authTrustLevel,
        sptr<IIamCallback> &callback);
    void StopAllRunTask(const ResultCode &resultCode);
    std::string BuildStartCommand(const WidgetRotatePara &widgetRotatePara);
    void BuildStartPinSubType(WidgetCmdParameters &widgetCmdParameters);
    void ProcessRotatePara(WidgetCmdParameters &widgetCmdParameters, const WidgetRotatePara &widgetRotatePara);
    bool IsValidRotate(const WidgetRotatePara &widgetRotatePara);
    std::string GetCallingBundleName();
    bool IsSupportFollowCallerUi();
    bool IsInFollowCallerList();
    void SetSysDialogZOrder(WidgetCmdParameters &widgetCmdParameters);
    bool IsSingleFaceOrFingerPrintAuth();
    bool IsNavigationAuth();
    bool IsSingleCompanionDeviceAuth() const;
    UserAuthTipCode GetAuthTipCode(int32_t authResult, int32_t freezingTime);
    void ProcAuthResult(int32_t resultCode, AuthType authType, int32_t freezingTime,
        const Attributes &finalResult);
    void ProcAuthTipInfo(int32_t tip, AuthType authType, const std::vector<uint8_t> &extraInfo);
    void StartOnTerminateTimer();
    void StopOnTerminateTimer();
    void OnTerminateTimerTimeOut(uint64_t contextId);
    void StartRemoteAuthTimer();
    void StopRemoteAuthTimer();
    void OnRemoteAuthTimerTimeOut();
    std::string ProcessCmdData(WidgetCmdParameters &widgetCmdParameters);
    void ProcessElementName(std::string &bundleName, std::string &abilityName);
    bool HandleAuthSuccessResult(Attributes &attr);

private:
    struct TaskInfo {
        AuthType authType {0};
        std::shared_ptr<Context> task {nullptr};
    };

    struct WidgetAuthResultInfo {
        std::vector<uint8_t> token {};
        AuthType authType {0};
        uint64_t credentialDigest;
        uint16_t credentialCount;
        int64_t pinExpiredInfo;
        int32_t resultUserId;
    };

    struct ResultInfo {
        int32_t resultCode;
        AuthType authType;
        int32_t freezingTime;
    };

    uint64_t contextId_ {0};
    std::string description_ {""};
    std::shared_ptr<ContextCallback> callerCallback_ {nullptr};
    bool hasStarted_ {false};
    bool useModalApplication_ {false};

    int32_t latestError_ {ResultCode::GENERAL_ERROR};
    ContextFactory::AuthWidgetContextPara para_ {};
    bool isDirectAuth_ {false};
    std::shared_ptr<WidgetScheduleNode> schedule_ {nullptr};
    sptr<IModalCallback> modalCallback_ {nullptr};
    sptr<IRemoteAuthCallback> remoteAuthCallback_ {nullptr};
    std::recursive_mutex mutex_;
    std::list<TaskInfo> runTaskInfoList_;
    sptr<UIExtensionAbilityConnection> connection_ {nullptr};
    WidgetAuthResultInfo authResultInfo_ {};
    int32_t faceReload_ {0};
    uint32_t widgetAlreadyLoad_ {0};
    nlohmann::json jsonBuf_ = {};
    uint32_t onTerminateTimerId_ {0};
    uint32_t remoteAuthTimerId_ {0};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_WIDGET_CONTEXT_H
