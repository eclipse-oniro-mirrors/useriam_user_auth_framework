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
#include "widget_context.h"

#include <algorithm>
#include "bool_wrapper.h"
#include "double_wrapper.h"
#include "int_wrapper.h"
#include "refbase.h"

#include "ability_connection.h"
#include "ability_connect_callback.h"
#include "accesstoken_kit.h"
#include "auth_widget_helper.h"
#include "context_helper.h"
#include "context_pool.h"
#include "context_death_recipient.h"
#include "hisysevent_adapter.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "iam_time.h"
#include "parameters.h"
#include "relative_timer.h"
#include "schedule_node.h"
#include "schedule_node_callback.h"
#include "set_widget_param_callback_service.h"
#include "string_wrapper.h"
#include "system_ability_definition.h"
#include "want_params_wrapper.h"
#include "widget_schedule_node_impl.h"
#include "widget_context_callback_impl.h"
#include "widget_client.h"
#include <sys/stat.h>
#ifdef SCENE_BOARD_ENABLE
#include "display_manager_lite.h"
#else
#include "display_manager.h"
#endif

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_WIDGET_CONTEXT

namespace OHOS {
namespace UserIam {
namespace UserAuth {
constexpr int32_t DEFAULT_VALUE = -1;
const std::string UI_EXTENSION_TYPE_SET = "sysDialog/userAuth";
const uint32_t SYSDIALOG_ZORDER_DEFAULT = 1;
const uint32_t SYSDIALOG_ZORDER_UPPER = 2;
const uint32_t SYSDIALOG_FOCUS_STATE_ENABLE = 1;
const uint32_t ORIENTATION_LANDSCAPE = 1;
const uint32_t ORIENTATION_PORTRAIT_INVERTED = 2;
const uint32_t ORIENTATION_LANDSCAPE_INVERTED = 3;
const std::string TO_PORTRAIT = "90";
const std::string TO_INVERTED = "180";
const std::string TO_PORTRAIT_INVERTED = "270";
const std::string SUPPORT_FOLLOW_CALLER_UI = "const.useriam.authWidget.supportFollowCallerUi";
#ifndef IAM_TEST_ENABLE
static constexpr uint32_t TERMINATE_TIMER_LEN_MS = 3000;
#else
static constexpr uint32_t TERMINATE_TIMER_LEN_MS = 1000;
#endif
static constexpr uint32_t REMOTE_AUTH_TIMER_LEN_MS = 10000;

WidgetContext::WidgetContext(uint64_t contextId, const ContextFactory::AuthWidgetContextPara &para,
    std::shared_ptr<ContextCallback> callback, const sptr<IModalCallback> &modalCallback,
    const sptr<IRemoteAuthCallback> &remoteAuthCallback)
    : contextId_(contextId), description_("UserAuthWidget"), callerCallback_(callback), hasStarted_(false),
    latestError_(ResultCode::GENERAL_ERROR), para_(para), schedule_(nullptr), modalCallback_(modalCallback),
    remoteAuthCallback_(remoteAuthCallback), connection_(nullptr)
{
    callback->SetTraceIsWidgetAuth(true);
    AddDeathRecipient(callerCallback_, contextId_);
    if (!para.isBackgroundApplication) {
        SubscribeAppState(callerCallback_, contextId_);
    }
    LoadConfigJsonBuffer(jsonBuf_);
}

WidgetContext::~WidgetContext()
{
    IAM_LOGD("release WidgetContext");
    StopOnTerminateTimer();
    RemoveDeathRecipient(callerCallback_);
    UnSubscribeAppState();
}

bool WidgetContext::Start()
{
    IAM_LOGD("%{public}s start", description_.c_str());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (hasStarted_) {
        IAM_LOGI("%{public}s context has started, cannot start again", description_.c_str());
        return false;
    }
    hasStarted_ = true;
    return OnStart();
}

bool WidgetContext::Stop()
{
    IAM_LOGI("%{public}s start", description_.c_str());
    return OnStop();
}

uint64_t WidgetContext::GetContextId() const
{
    return contextId_;
}

ContextType WidgetContext::GetContextType() const
{
    return WIDGET_AUTH_CONTEXT;
}

std::shared_ptr<ScheduleNode> WidgetContext::GetScheduleNode(uint64_t scheduleId) const
{
    return nullptr;
}

uint32_t WidgetContext::GetTokenId() const
{
    return para_.tokenId;
}

int32_t WidgetContext::GetUserId() const
{
    return para_.userId;
}

int32_t WidgetContext::GetAuthType() const
{
    return INVALID_AUTH_TYPE;
}

std::string WidgetContext::GetCallerName() const
{
    return para_.callerName;
}

int32_t WidgetContext::GetLatestError() const
{
    return latestError_;
}

void WidgetContext::SetLatestError(int32_t error)
{
    if (error != ResultCode::SUCCESS) {
        latestError_ = error;
    }
}

bool WidgetContext::BuildSchedule()
{
    schedule_ = Common::MakeShared<WidgetScheduleNodeImpl>();
    IF_FALSE_LOGE_AND_RETURN_VAL(schedule_ != nullptr, false);
    schedule_->SetCallback(shared_from_this());
    return true;
}

std::shared_ptr<ContextCallback> WidgetContext::GetAuthContextCallback(AuthType authType,
    AuthTrustLevel authTrustLevel, sptr<IIamCallback> &iamCallback)
{
    auto widgetCallback = ContextCallback::NewInstance(iamCallback, TRACE_AUTH_USER_SECURITY);
    if (widgetCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        Attributes extraInfo;
        iamCallback->OnResult(ResultCode::GENERAL_ERROR, extraInfo.Serialize());
        return nullptr;
    }
    widgetCallback->SetTraceCallerName(para_.callerName);
    widgetCallback->SetTraceCallerType(para_.callerType);
    widgetCallback->SetTraceRequestContextId(contextId_);
    widgetCallback->SetTraceAuthTrustLevel(authTrustLevel);
    widgetCallback->SetTraceAuthType(authType);
    return widgetCallback;
}

std::shared_ptr<Context> WidgetContext::BuildTask(const std::vector<uint8_t> &challenge,
    AuthType authType, AuthTrustLevel authTrustLevel, bool endAfterFirstFail, AuthIntent authIntent)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(callerCallback_ != nullptr, nullptr);
    auto userId = para_.userId;
    auto tokenId = WidgetClient::Instance().GetAuthTokenId();
    IAM_LOGI("Real userId: %{public}d, Real tokenId: %{public}s", userId, GET_MASKED_STRING(tokenId).c_str());
    sptr<IIamCallback> iamCallback(new (std::nothrow) WidgetContextCallbackImpl(weak_from_this(),
        static_cast<int32_t>(authType)));
    IF_FALSE_LOGE_AND_RETURN_VAL(iamCallback != nullptr, nullptr);
    auto widgetCallback = GetAuthContextCallback(authType, authTrustLevel, iamCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(widgetCallback != nullptr, nullptr);

    Authentication::AuthenticationPara para = {};
    para.tokenId = tokenId;
    para.userId = userId;
    para.authType = authType;
    para.atl = authTrustLevel;
    para.challenge = challenge;
    para.endAfterFirstFail = endAfterFirstFail;
    para.callerName = para_.callerName;
    para.callerType = para_.callerType;
    para.sdkVersion = para_.sdkVersion;
    para.authIntent = authIntent;
    para.skipLockedBiometricAuth = para_.skipLockedBiometricAuth;
    para.isOsAccountVerified = para_.isOsAccountVerified;
    para.credentialIdList = para_.credentialIdList;
    para.title = para_.widgetParam.title;
    para.authScene = AuthScene::AUTH_SCENE_WIDGET_AUTH_NO_DISTURB;
    auto context = ContextFactory::CreateSimpleAuthContext(para, widgetCallback, true);
    if (context == nullptr || !ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        Attributes extraInfo;
        widgetCallback->SetTraceAuthFinishReason("WidgetContext BuildTask insert context fail");
        widgetCallback->OnResult(ResultCode::GENERAL_ERROR, extraInfo);
        return nullptr;
    }
    widgetCallback->SetTraceAuthContextId(context->GetContextId());
    widgetCallback->SetCleaner(ContextHelper::Cleaner(context));
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return context;
}

bool WidgetContext::OnStart()
{
    IAM_LOGI("%{public}s start", description_.c_str());
    if (!BuildSchedule()) {
        IAM_LOGE("failed to create widget schedule");
        return false;
    }
    IF_FALSE_LOGE_AND_RETURN_VAL(schedule_ != nullptr, false);
    isDirectAuth_ = IsSingleCompanionDeviceAuth();
    WidgetClient::Instance().SetWidgetParam(para_.widgetParam);
    WidgetClient::Instance().SetAuthTypeList(para_.authTypeList);
    WidgetClient::Instance().SetWidgetSchedule(GetContextId(), schedule_);
    WidgetClient::Instance().SetChallenge(para_.challenge);
    WidgetClient::Instance().SetCallingBundleName(GetCallingBundleName());
    if (isDirectAuth_) {
        IAM_LOGI("direct auth mode, skip widget UI, authTypeList size: %{public}zu",
            para_.authTypeList.size());
        schedule_->StartAuthList(para_.authTypeList, false, AuthIntent::DEFAULT);
        if (!schedule_->StartDirectAuth()) {
            IAM_LOGE("StartDirectAuth failed");
            return false;
        }
    } else if (remoteAuthCallback_) {
        if (!schedule_->GetRemoteAuthParam()) {
            IAM_LOGE("GetRemoteAuthParam failed");
            return false;
        }
    } else {
        IAM_LOGI("widget auth mode, launch widget UI");
        if (!schedule_->StartSchedule()) {
            IAM_LOGE("StartSchedule failed");
            return false;
        }
    }
    IAM_LOGI("WidgetContext start success.");
    return true;
}

void WidgetContext::OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr)
{
    IAM_LOGI("%{public}s receive result code %{public}d", description_.c_str(), resultCode);
}

bool WidgetContext::OnStop()
{
    // response app.cancel()
    IAM_LOGI("%{public}s start", description_.c_str());
    End(ResultCode::CANCELED);
    WidgetClient::Instance().ClearSchedule(contextId_);
    return true;
}

void WidgetContext::AuthResult(int32_t resultCode, int32_t authType, const Attributes &finalResult)
{
    HILOG_COMM_INFO("widget context: ****%{public}hx recv task result: %{public}d, authType: %{public}d",
        static_cast<uint16_t>(contextId_), resultCode, authType);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    int32_t remainTimes = -1;
    int32_t freezingTime = -1;
    if (!finalResult.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, remainTimes)) {
        IAM_LOGI("get remainTimes failed.");
    }
    if (!finalResult.GetInt32Value(Attributes::ATTR_FREEZING_TIME, freezingTime)) {
        IAM_LOGI("get freezingTime failed.");
    }
    AuthType authTypeTmp = static_cast<AuthType>(authType);
    WidgetClient::Instance().ReportWidgetResult(resultCode, authTypeTmp, freezingTime, remainTimes,
        para_.skipLockedBiometricAuth);
    IF_FALSE_LOGE_AND_RETURN(callerCallback_ != nullptr);
    callerCallback_->SetTraceAuthType(authTypeTmp);
    IAM_LOGD("call schedule:");
    ProcAuthResult(resultCode, authTypeTmp, freezingTime, finalResult);
}

void WidgetContext::AuthTipInfo(int32_t tipType, int32_t authType, const Attributes &extraInfo)
{
    HILOG_COMM_INFO("widget context: ****%{public}hx recv tip: %{public}d, authType: %{public}d",
        static_cast<uint16_t>(contextId_), tipType, authType);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<uint8_t> tipInfo;
    bool getTipInfoRet = extraInfo.GetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, tipInfo);
    IF_FALSE_LOGE_AND_RETURN(getTipInfoRet);
    WidgetClient::Instance().ReportWidgetTip(tipType, static_cast<AuthType>(authType), tipInfo,
        para_.skipLockedBiometricAuth);
    ProcAuthTipInfo(tipType, static_cast<AuthType>(authType), tipInfo);
}

// WidgetScheduleNodeCallback
bool WidgetContext::LaunchWidget()
{
    IAM_LOGI("launch widget");
    WidgetRotatePara widgetRotatePara;
    widgetRotatePara.isReload = false;
    widgetRotatePara.needRotate = 0;
    if (!ConnectExtension(widgetRotatePara)) {
        HILOG_COMM_ERROR("widget context: ****%{public}hx, failed to launch widget.",
            static_cast<uint16_t>(contextId_));
        return false;
    }
    return true;
}

void WidgetContext::ExecuteAuthList(const std::set<AuthType> &authTypeList, bool endAfterFirstFail,
    AuthIntent authIntent)
{
    IAM_LOGI("execute auth list, size: %{public}zu", authTypeList.size());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (auto &authType : authTypeList) {
        auto task = BuildTask(para_.challenge, authType, para_.atl, endAfterFirstFail, authIntent);
        if (task == nullptr) {
            IAM_LOGE("failed to create task, authType: %{public}s", AuthType2Str(authType).c_str());
            continue;
        }
        if (!task->Start()) {
            HILOG_COMM_ERROR("widget context: ****%{public}hx execute auth list failed, authType: %{public}d,"
                " atl: %{public}d, endAfterFirstFail: %{public}d, authIntent: %{public}d",
                static_cast<uint16_t>(contextId_), authType, para_.atl, endAfterFirstFail, authIntent);
            static const int32_t INVALID_VAL = -1;
            WidgetClient::Instance().ReportWidgetResult(task->GetLatestError(), authType, INVALID_VAL, INVALID_VAL,
                para_.skipLockedBiometricAuth);
            return;
        }
        if (authType == FACE) {
            faceReload_ = 1;
            IAM_LOGI("faceReload_: %{public}d", faceReload_);
        }
        TaskInfo taskInfo {
            .authType = authType,
            .task = task
        };
        runTaskInfoList_.push_back(taskInfo);
    }
}

void WidgetContext::EndAuthAsCancel()
{
    IAM_LOGI("end auth as cancel");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (latestError_ == COMPLEXITY_CHECK_FAILED) {
        IAM_LOGE("complexity check failed");
        return End(TRUST_LEVEL_NOT_SUPPORT);
    }
    if (connection_ != nullptr && connection_->GetOnResultEnd()) {
        HILOG_COMM_ERROR("widget context: ****%{public}hx send result end", static_cast<uint16_t>(contextId_));
        return;
    }
    // report CANCELED to App
    End(ResultCode::CANCELED);
}

void WidgetContext::EndAuthAsNaviPin()
{
    IAM_LOGI("end auth as navi pin");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    // report CANCELED_FROM_WIDGET to App
    End(ResultCode::CANCELED_FROM_WIDGET);
}

void WidgetContext::EndAuthAsWidgetParaInvalid()
{
    IAM_LOGI("end auth as widget para invalid");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    End(ResultCode::INVALID_PARAMETERS);
}

void WidgetContext::AuthWidgetReloadInit()
{
    IAM_LOGI("auth widget reload init");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!DisconnectExtension()) {
        HILOG_COMM_ERROR("widget context: ****%{public}hx failed to release launch widget",
            static_cast<uint16_t>(contextId_));
    }
}

bool WidgetContext::AuthWidgetReload(uint32_t orientation, uint32_t needRotate, uint32_t alreadyLoad,
    AuthType &rotateAuthType)
{
    IAM_LOGI("auth widget reload");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    WidgetRotatePara widgetRotatePara;
    widgetRotatePara.isReload = true;
    widgetRotatePara.orientation = orientation;
    widgetRotatePara.needRotate = needRotate;
    widgetRotatePara.alreadyLoad = alreadyLoad;
    widgetRotatePara.rotateAuthType = rotateAuthType;
    if (alreadyLoad) {
        widgetAlreadyLoad_ = 1;
    }
    if (!IsValidRotate(widgetRotatePara)) {
        IAM_LOGE("check rotate failed");
        return false;
    }
    if (!ConnectExtension(widgetRotatePara)) {
        HILOG_COMM_ERROR("widget context: ****%{public}hx failed to reload widget",
            static_cast<uint16_t>(contextId_));
        return false;
    }
    return true;
}

bool WidgetContext::IsValidRotate(const WidgetRotatePara &widgetRotatePara)
{
    IAM_LOGI("check rotate, needRotate: %{public}u, orientation: %{public}u", widgetRotatePara.needRotate,
        widgetRotatePara.orientation);
    if (widgetRotatePara.needRotate) {
        IAM_LOGI("check rotate, widgetAlreadyLoad_: %{public}u", widgetAlreadyLoad_);
        if (widgetRotatePara.orientation == ORIENTATION_PORTRAIT_INVERTED && !widgetAlreadyLoad_) {
            IAM_LOGI("only support first");
            return true;
        }
    }
    return true;
}

void WidgetContext::StopAuthList(const std::vector<AuthType> &authTypeList)
{
    IAM_LOGI("stop auth list");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (auto &authType : authTypeList) {
        auto it = std::find_if(runTaskInfoList_.begin(),
            runTaskInfoList_.end(), [authType] (const TaskInfo &taskInfo) {
            return (taskInfo.authType == authType);
        });
        if (it != runTaskInfoList_.end()) {
            if (it->task == nullptr) {
                IAM_LOGE("task is nullptr");
                return;
            }
            it->task->Stop();
            IAM_LOGI("stop task, authType: %{public}d", static_cast<int32_t>(authType));
            runTaskInfoList_.erase(it);
        }
    }
}

void WidgetContext::SuccessAuth(AuthType authType)
{
    IAM_LOGI("success auth. authType:%{public}d", static_cast<int32_t>(authType));
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    // report success to App
    if (latestError_ == ResultCode::COMPLEXITY_CHECK_FAILED) {
        IAM_LOGE("complexity check failed");
        End(TRUST_LEVEL_NOT_SUPPORT);
        return;
    }
    End(ResultCode::SUCCESS);
}

void WidgetContext::FailAuth(AuthType authType)
{
    IAM_LOGI("fail auth. authType:%{public}d", static_cast<int32_t>(authType));
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    End(static_cast<ResultCode>(GetLatestError()));
}

int32_t WidgetContext::ConnectExtensionAbility(const AAFwk::Want &want, const std::string commandStr)
{
    HILOG_COMM_INFO("widget context: ****%{public}hx ConnectExtensionAbility start",
        static_cast<uint16_t>(contextId_));
    if (connection_ != nullptr) {
        IAM_LOGE("invalid connection_");
        return ERR_INVALID_OPERATION;
    }
    connection_ = sptr<UIExtensionAbilityConnection>(new (std::nothrow) UIExtensionAbilityConnection(commandStr));
    if (connection_ == nullptr) {
        IAM_LOGE("new connection error.");
        return ERR_NO_MEMORY;
    }

    std::string identity = IPCSkeleton::ResetCallingIdentity();
#ifdef IAM_TEST_ENABLE
    return SUCCESS;
#endif
    auto ret = AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(want, connection_, nullptr,
        DEFAULT_VALUE);
    IPCSkeleton::SetCallingIdentity(identity);
    IAM_LOGI("ConnectExtensionAbility errCode=%{public}d", ret);
    return ret;
}

bool WidgetContext::IsInFollowCallerList()
{
    IAM_LOGI("enter");
    std::string devicecollaboration = "com.huawei.hmos.devicecollaboration";
    if (devicecollaboration == para_.remoteCallerName) {
        IAM_LOGI("callerName is from cache, skip follow caller list check");
        return true;
    }

#ifdef SCENE_BOARD_ENABLE
    auto foldStatus = Rosen::DisplayManagerLite::GetInstance().GetFoldStatus();
#else
    auto foldStatus = Rosen::DisplayManager::GetInstance().GetFoldStatus();
#endif
    IAM_LOGI("FoldStatus is %{public}d.", foldStatus);
    if (foldStatus != Rosen::FoldStatus::FOLDED) {
        return false;
    }

    std::string productName = OHOS::system::GetParameter("const.build.product", "");
    IAM_LOGI("productName is %{public}s.", productName.c_str());

    std::vector<std::string> processName;
    if (!GetFollowCallerList(jsonBuf_, processName)) {
        IAM_LOGE("GetFollowCallerList error");
        return false;
    }
    for (auto it = processName.begin(); it != processName.end(); ++it) {
        if (productName + "-" == *it) {
            return true;
        }
    }
    return false;
}

bool WidgetContext::IsSupportFollowCallerUi()
{
    bool isSupportFollowCallerUi = OHOS::system::GetParameter(SUPPORT_FOLLOW_CALLER_UI, "false") == "true";
    IAM_LOGI("is support follow caller UI: %{public}d", isSupportFollowCallerUi);
    return isSupportFollowCallerUi || IsInFollowCallerList();
}

void WidgetContext::SetSysDialogZOrder(WidgetCmdParameters &widgetCmdParameters)
{
    IAM_LOGI("enter");
    std::vector<std::string> processName;
    if (ContextAppStateObserverManager::GetInstance().IsScreenLocked()) {
        IAM_LOGI("the screen is currently locked, set zOrder");
        widgetCmdParameters.sysDialogZOrder = SYSDIALOG_ZORDER_UPPER;
    }
    if (!GetProcessName(jsonBuf_, processName)) {
        IAM_LOGE("getProcessName error");
        return;
    }
    for (auto it = processName.begin(); it != processName.end(); ++it) {
        if ((para_.callerName == *it) && (para_.callerType == Security::AccessToken::TOKEN_NATIVE)) {
            IAM_LOGI("is on shutdown screen, set zOrder");
            widgetCmdParameters.useriamCmdData.callingProcessName = para_.callerName;
            widgetCmdParameters.sysDialogZOrder = SYSDIALOG_ZORDER_UPPER;
            break;
        }
    }
}

bool WidgetContext::ConnectExtension(const WidgetRotatePara &widgetRotatePara)
{
    IAM_LOGI("connect extension start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (widgetRotatePara.isReload) {
        for (auto &authType : para_.authTypeList) {
            ContextFactory::AuthProfile profile;
            if (!AuthWidgetHelper::GetUserAuthProfile(para_.userId, authType, profile, para_.credentialIdList)) {
                IAM_LOGE("get user authType:%{public}d profile failed", static_cast<int32_t>(authType));
                return false;
            }
            para_.authProfileMap[authType] = profile;
        }
    }

    if (IsSingleFaceOrFingerPrintAuth() && para_.skipLockedBiometricAuth &&
        para_.authProfileMap[para_.authTypeList[0]].remainTimes == 0) {
        Attributes attr;
        callerCallback_->OnResult(ResultCode::LOCKED, attr);
        if (remoteAuthCallback_ != nullptr) {
            remoteAuthCallback_->OnRemoteAuthResult(para_.challenge, ResultCode::LOCKED, attr.Serialize());
        }
        UnSubscribeAppState();
        return true;
    }

    std::string commandData = BuildStartCommand(widgetRotatePara);
    IAM_LOGI("start command: %{public}s", commandData.c_str());
    if (commandData.size() == 0) {
        return false;
    }

    IAM_LOGI("has context: %{public}d", para_.widgetParam.hasContext);
    if (para_.widgetParam.hasContext && IsSupportFollowCallerUi()) {
        // As modal application
        // No need do anything, caller death has process; only process timeout for widget.
        useModalApplication_ = true;
        if (modalCallback_ != nullptr) {
            modalCallback_->SendCommand(contextId_, commandData);
        }
        return true;
    }
    // Default as modal system
    AAFwk::Want want;
    std::string bundleName = "com.ohos.systemui";
    std::string abilityName = "com.ohos.systemui.dialog";
    ProcessElementName(bundleName, abilityName);
    want.SetElementName(bundleName, abilityName);
    auto ret = ConnectExtensionAbility(want, commandData);
    if (ret != ERR_OK) {
        UserIam::UserAuth::ReportSystemFault(Common::GetNowTimeString(), "userauthservice");
        HILOG_COMM_ERROR("widget context: ****%{public}hx ConnectExtensionAbility failed, ret: %{public}d",
            static_cast<uint16_t>(contextId_), ret);
        return false;
    }
    return true;
}

void WidgetContext::ProcessElementName(std::string &bundleName, std::string &abilityName)
{
    if (!GetSceneboardBundleName(jsonBuf_, bundleName)) {
        IAM_LOGI("GetSceneboardBundleName error");
    }
    if (!GetSceneboardAbilityName(jsonBuf_, abilityName)) {
        IAM_LOGI("GetSceneboardAbilityName error");
    }
}

bool WidgetContext::DisconnectExtension()
{
    IAM_LOGI("has context: %{public}d", para_.widgetParam.hasContext);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if ((para_.widgetParam.hasContext && IsSupportFollowCallerUi()) || useModalApplication_) {
        // As modal application release.
        if (schedule_ != nullptr) {
            schedule_->StopSchedule();
        }
        if (modalCallback_ != nullptr) {
            std::string cmdData = "";
            modalCallback_->SendCommand(contextId_, cmdData);
        }
        return true;
    }
    // Default as modal system release.
    if (connection_ == nullptr) {
        IAM_LOGE("invalid connection handle");
        return false;
    }
    if (schedule_ != nullptr) {
        schedule_->StopSchedule();
    }
    connection_->ReleaseUIExtensionComponent();
    ErrCode ret = AAFwk::ExtensionManagerClient::GetInstance().DisconnectAbility(connection_);
    connection_ = nullptr;
    if (ret != ERR_OK) {
        HILOG_COMM_ERROR("widget context: ****%{public}hx disconnect extension ability failed ret: %{public}d.",
            static_cast<uint16_t>(contextId_), ret);
        return false;
    }
    return true;
}

bool WidgetContext::HandleAuthSuccessResult(Attributes &attr)
{
    if (!attr.SetInt32Value(Attributes::ATTR_AUTH_TYPE, authResultInfo_.authType)) {
        IAM_LOGE("set auth type failed.");
        callerCallback_->SetTraceAuthFinishReason("WidgetContext End set authType fail");
        goto EXIT;
    }
    if (authResultInfo_.token.size() > 0) {
        if (!attr.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, authResultInfo_.token)) {
            IAM_LOGE("set signature token failed.");
            callerCallback_->SetTraceAuthFinishReason("WidgetContext End set token fail");
            goto EXIT;
        }
    }
    IAM_LOGI("in End, token size: %{public}zu.", authResultInfo_.token.size());
    if (!attr.SetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST, authResultInfo_.credentialDigest)) {
        IAM_LOGE("set credential digest failed.");
        callerCallback_->SetTraceAuthFinishReason("WidgetContext End set credentialDigest fail");
        goto EXIT;
    }
    if (!attr.SetUint16Value(Attributes::ATTR_CREDENTIAL_COUNT, authResultInfo_.credentialCount)) {
        IAM_LOGE("set credential count failed.");
        callerCallback_->SetTraceAuthFinishReason("WidgetContext End set credentialCount fail");
        goto EXIT;
    }
    if (!attr.SetInt32Value(Attributes::ATTR_USER_ID, authResultInfo_.resultUserId)) {
        IAM_LOGE("set user id failed.");
        callerCallback_->SetTraceAuthFinishReason("WidgetContext End set userId fail");
        goto EXIT;
    }
    return true;

EXIT:
    callerCallback_->OnResult(ResultCode::GENERAL_ERROR, attr);
    if (remoteAuthCallback_ != nullptr) {
        remoteAuthCallback_->OnRemoteAuthResult(para_.challenge, ResultCode::GENERAL_ERROR, attr.Serialize());
    }
    return false;
}

void WidgetContext::End(const ResultCode &resultCode)
{
    HILOG_COMM_INFO("widget context: ****%{public}hx in End, resultCode: %{public}d",
        static_cast<uint16_t>(contextId_), static_cast<int32_t>(resultCode));
    StopAllRunTask(resultCode);
    IF_FALSE_LOGE_AND_RETURN(callerCallback_ != nullptr);
    Attributes attr;
    if (resultCode == ResultCode::SUCCESS || authResultInfo_.token.size() != 0) {
        if (!HandleAuthSuccessResult(attr)) {
            goto EXIT;
        }
    }
    callerCallback_->OnResult(resultCode, attr);
    if (remoteAuthCallback_ != nullptr) {
        remoteAuthCallback_->OnRemoteAuthResult(para_.challenge, resultCode, attr.Serialize());
    }
    if (connection_ == nullptr) {
        IAM_LOGE("invalid connection handle");
        goto EXIT;
    }
    connection_->setIsNormalEnd(true);
EXIT:
    StartOnTerminateTimer();
    UnSubscribeAppState();
}

void WidgetContext::StopAllRunTask(const ResultCode &resultCode)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (auto &taskInfo : runTaskInfoList_) {
        IAM_LOGD("stop task");
        if (taskInfo.task == nullptr) {
            IAM_LOGE("task is null");
            continue;
        }
        taskInfo.task->Stop();
    }
    runTaskInfoList_.clear();
    if (resultCode != ResultCode::SUCCESS) {
        IAM_LOGI("Try to disconnect extension");
        if (!DisconnectExtension()) {
            IAM_LOGE("failed to release launch widget.");
        }
    }
}

void WidgetContext::BuildStartPinSubType(WidgetCmdParameters &widgetCmdParameters)
{
    auto it = para_.authProfileMap.find(AuthType::PIN);
    if (it == para_.authProfileMap.end()) {
        it = para_.authProfileMap.find(AuthType::PRIVATE_PIN);
    }
    if (it != para_.authProfileMap.end()) {
        widgetCmdParameters.useriamCmdData.pinSubType = PinSubType2Str(static_cast<PinSubType>(it->second.pinSubType));
    }
}

std::string WidgetContext::BuildStartCommand(const WidgetRotatePara &widgetRotatePara)
{
    WidgetCmdParameters widgetCmdParameters;
    widgetCmdParameters.uiExtensionType = UI_EXTENSION_TYPE_SET;
    widgetCmdParameters.useriamCmdData.widgetContextId = GetContextId();
    widgetCmdParameters.useriamCmdData.widgetContextIdStr = std::to_string(GetContextId());
    widgetCmdParameters.useriamCmdData.title = para_.widgetParam.title;
    widgetCmdParameters.useriamCmdData.windowModeType = WinModeType2Str(para_.widgetParam.windowMode);
    widgetCmdParameters.useriamCmdData.navigationButtonText = para_.widgetParam.navigationButtonText;
    BuildStartPinSubType(widgetCmdParameters);
    widgetCmdParameters.sysDialogZOrder = SYSDIALOG_ZORDER_DEFAULT;
    widgetCmdParameters.focusState = SYSDIALOG_FOCUS_STATE_ENABLE;
    SetSysDialogZOrder(widgetCmdParameters);
    std::vector<std::string> typeList;
    for (auto &item : para_.authProfileMap) {
        auto &at = item.first;
        auto &profile = item.second;
        typeList.push_back(AuthType2Str(at));
        WidgetCommand::Cmd cmd {
            .event = CMD_NOTIFY_AUTH_START,
            .version = NOTICE_VERSION_STR,
            .type = AuthType2Str(at)
        };
        if (at == AuthType::FINGERPRINT && !profile.sensorInfo.empty()) {
            cmd.sensorInfo = profile.sensorInfo;
        }
        if (para_.isPinExpired) {
            cmd.result = PIN_EXPIRED;
        }
        cmd.remainAttempts = profile.remainTimes;
        cmd.lockoutDuration = profile.freezingTime;
        WidgetCommand::ExtraInfo extraInfo = {};
        if (remoteAuthCallback_) {
            extraInfo.callingBundleName = para_.remoteCallerName;
            extraInfo.challenge = para_.challenge;
        } else {
            extraInfo.callingBundleName = GetCallingBundleName();
            extraInfo.challenge = para_.challenge;
        }
        cmd.extraInfo = extraInfo;
        widgetCmdParameters.useriamCmdData.cmdList.push_back(cmd);
    }
    widgetCmdParameters.useriamCmdData.typeList = typeList;
    widgetCmdParameters.useriamCmdData.callingAppID = para_.callingAppID;
    widgetCmdParameters.useriamCmdData.userId = para_.userId;
    widgetCmdParameters.useriamCmdData.skipLockedBiometricAuth = para_.skipLockedBiometricAuth;
    ProcessRotatePara(widgetCmdParameters, widgetRotatePara);
    return ProcessCmdData(widgetCmdParameters);
}

std::string WidgetContext::ProcessCmdData(WidgetCmdParameters &widgetCmdParameters)
{
    nlohmann::json root = widgetCmdParameters;
    std::string cmdData;
    try {
        cmdData = root.dump();
    } catch (const nlohmann::json::exception &e) {
        cmdData = "";
        IAM_LOGE("cmd is invalid json, error: %{public}s", e.what());
    }
    return cmdData;
}

void WidgetContext::ProcessRotatePara(WidgetCmdParameters &widgetCmdParameters,
    const WidgetRotatePara &widgetRotatePara)
{
    if (widgetRotatePara.isReload) {
        widgetCmdParameters.useriamCmdData.isReload = 1;
        if (widgetRotatePara.rotateAuthType == FACE) {
            widgetCmdParameters.useriamCmdData.isReload = faceReload_;
        }
        widgetCmdParameters.useriamCmdData.rotateAuthType = AuthType2Str(widgetRotatePara.rotateAuthType);
    }
    IAM_LOGI("needRotate: %{public}u, orientation: %{public}u", widgetRotatePara.needRotate,
        widgetRotatePara.orientation);
    if (widgetRotatePara.needRotate) {
        if (widgetRotatePara.orientation == ORIENTATION_LANDSCAPE) {
            widgetCmdParameters.uiExtNodeAngle = TO_PORTRAIT;
        }
        if (widgetRotatePara.orientation == ORIENTATION_PORTRAIT_INVERTED) {
            widgetCmdParameters.uiExtNodeAngle = TO_INVERTED;
        }
        if (widgetRotatePara.orientation == ORIENTATION_LANDSCAPE_INVERTED) {
            widgetCmdParameters.uiExtNodeAngle = TO_PORTRAIT_INVERTED;
        }
    }
}

std::string WidgetContext::GetCallingBundleName()
{
    if (para_.callerType == Security::AccessToken::TOKEN_HAP) {
        return para_.callerName;
    }
    return "";
}

bool WidgetContext::IsSingleFaceOrFingerPrintAuth()
{
    if (!para_.widgetParam.navigationButtonText.empty()) {
        return false;
    }
    if (para_.authTypeList.size() == 1 && (para_.authTypeList[0] == FACE || para_.authTypeList[0] == FINGERPRINT)) {
        return true;
    }
    return false;
}

bool WidgetContext::IsNavigationAuth()
{
    if (para_.widgetParam.navigationButtonText.empty()) {
        return false;
    }
    return true;
}

bool WidgetContext::IsSingleCompanionDeviceAuth() const
{
    if (para_.authTypeList.size() != 1) {
        return false;
    }
    return para_.authTypeList[0] == AuthType::COMPANION_DEVICE;
}

void WidgetContext::SendAuthTipInfo(int32_t authType, int32_t tipCode)
{
    HILOG_COMM_INFO("widget context: ****%{public}hx authType:%{public}d, tipCode:%{public}d",
        static_cast<uint16_t>(contextId_), authType, tipCode);
    Attributes attr;
    bool setTipInfoRet = attr.SetInt32Value(Attributes::ATTR_TIP_INFO, tipCode);
    if (!setTipInfoRet) {
        IAM_LOGE("set tipInfo fail");
        return;
    }

    IF_FALSE_LOGE_AND_RETURN(callerCallback_ != nullptr);

    callerCallback_->OnAcquireInfo(ALL_IN_ONE, authType, attr.Serialize());
}

UserAuthTipCode WidgetContext::GetAuthTipCode(int32_t authResult, int32_t freezingTime)
{
    UserAuthTipCode tipCode = TIP_CODE_FAIL;
    if (authResult == ResultCode::TIMEOUT) {
        tipCode = TIP_CODE_TIMEOUT;
    } else if (authResult == ResultCode::LOCKED) {
        if (freezingTime == INT32_MAX) {
            tipCode = TIP_CODE_PERMANENTLY_LOCKED;
        } else {
            tipCode = TIP_CODE_TEMPORARILY_LOCKED;
        }
    } else if (freezingTime > 0) {
        tipCode = TIP_CODE_COMPARE_FAIL_WITH_FROZEN;
    } else {
        tipCode = TIP_CODE_FAIL;
    }
    return tipCode;
}

void WidgetContext::ProcAuthResult(int32_t resultCode, AuthType authType, int32_t freezingTime,
    const Attributes &finalResult)
{
    HILOG_COMM_INFO("widget context: ****%{public}hx proc recv task result: %{public}d, authType: %{public}d",
        static_cast<uint16_t>(contextId_), resultCode, authType);
    IF_FALSE_LOGE_AND_RETURN(schedule_ != nullptr);
    if (resultCode == ResultCode::SUCCESS || resultCode == ResultCode::COMPLEXITY_CHECK_FAILED) {
        finalResult.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, authResultInfo_.token);
        finalResult.GetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST, authResultInfo_.credentialDigest);
        finalResult.GetUint16Value(Attributes::ATTR_CREDENTIAL_COUNT, authResultInfo_.credentialCount);
        authResultInfo_.authType = authType;
        IAM_LOGD("widget token size: %{public}zu.", authResultInfo_.token.size());
        if (resultCode != ResultCode::SUCCESS) {
            SetLatestError(resultCode);
        }
        schedule_->SuccessAuth(authType);
        if (isDirectAuth_) {
            schedule_->ClearSchedule();
        }
    } else {
        SetLatestError(resultCode);
        if (isDirectAuth_) {
            schedule_->FailAuth(authType);
            schedule_->ClearSchedule();
            return;
        }
        if (resultCode != ResultCode::CANCELED) {
            SendAuthTipInfo(authType, GetAuthTipCode(resultCode, freezingTime));
        }
        if (para_.skipLockedBiometricAuth && freezingTime > 0) {
            if (IsSingleFaceOrFingerPrintAuth()) {
                SetLatestError(ResultCode::LOCKED);
                schedule_->FailAuth(authType);
            } else if (IsNavigationAuth()) {
                schedule_->NaviPinAuth();
            }
        } else {
            schedule_->StopAuthList({authType});
        }
    }
}

void WidgetContext::ProcAuthTipInfo(int32_t tip, AuthType authType, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("authType:%{public}d, tip:%{public}d", authType, tip);
    IF_FALSE_LOGE_AND_RETURN(schedule_ != nullptr);
    IF_FALSE_LOGE_AND_RETURN(callerCallback_ != nullptr);
    int32_t resultCode = ResultCode::GENERAL_ERROR;
    int32_t freezingTime = -1;
    int32_t ret = callerCallback_->ParseAuthTipInfo(tip, extraInfo, resultCode, freezingTime);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("ParseAuthTipInfo fail");
        return;
    }
    if (resultCode == ResultCode::SUCCESS) {
        return;
    }
    if (resultCode != ResultCode::CANCELED) {
        SendAuthTipInfo(authType, GetAuthTipCode(resultCode, freezingTime));
    }
    if (para_.skipLockedBiometricAuth && freezingTime > 0) {
        if (IsSingleFaceOrFingerPrintAuth()) {
            SetLatestError(ResultCode::LOCKED);
            schedule_->FailAuth(authType);
        } else if (IsNavigationAuth()) {
            schedule_->NaviPinAuth();
        }
    }
}

void WidgetContext::StartOnTerminateTimer()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (onTerminateTimerId_ != 0) {
        IAM_LOGI("onTerminateTimer is already start");
        return;
    }
    uint64_t contextId = GetContextId();
    IAM_LOGI("onTerminateTimer start, context ****%{public}hx", static_cast<uint16_t>(contextId));
    onTerminateTimerId_ = RelativeTimer::GetInstance().Register(
        [weakSelf = weak_from_this(), contextId] {
            auto self = weakSelf.lock();
            if (self == nullptr) {
                IAM_LOGE("onTerminateTimer, context is released");
                return;
            }
            self->OnTerminateTimerTimeOut(contextId);
        },
        TERMINATE_TIMER_LEN_MS);
}

void WidgetContext::StopOnTerminateTimer()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (onTerminateTimerId_ == 0) {
        IAM_LOGI("onTerminateTimer is already stop");
        return;
    }

    RelativeTimer::GetInstance().Unregister(onTerminateTimerId_);
    onTerminateTimerId_ = 0;
}

void WidgetContext::OnTerminateTimerTimeOut(uint64_t contextId)
{
    IAM_LOGE("start");
    UserIam::UserAuth::ReportSystemFault(Common::GetNowTimeString(), "AuthWidget");
    WidgetClient::Instance().ClearSchedule(contextId);
}

void WidgetContext::ClearSchedule()
{
    IAM_LOGI("start");
    auto result = ContextPool::Instance().Delete(GetContextId());
    HILOG_COMM_INFO("widget context ****%{public}hx deleted %{public}s",
        static_cast<uint16_t>(contextId_), result ? "succ" : "fail");
}

void WidgetContext::StartRemoteAuthTimer()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (remoteAuthTimerId_ != 0) {
        IAM_LOGI("remoteAuthTimer is already start");
        return;
    }
    IAM_LOGI("remoteAuthTimer start, context ****%{public}hx", static_cast<uint16_t>(contextId_));
    remoteAuthTimerId_ = RelativeTimer::GetInstance().Register(
        [weakSelf = weak_from_this()] {
            auto self = weakSelf.lock();
            if (self == nullptr) {
                IAM_LOGE("remoteAuthTimer, context is released");
                return;
            }
            self->OnRemoteAuthTimerTimeOut();
        },
        REMOTE_AUTH_TIMER_LEN_MS);
}

void WidgetContext::StopRemoteAuthTimer()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (remoteAuthTimerId_ == 0) {
        IAM_LOGI("remoteAuthTimer is already stop");
        return;
    }

    RelativeTimer::GetInstance().Unregister(remoteAuthTimerId_);
    remoteAuthTimerId_ = 0;
}

void WidgetContext::OnRemoteAuthTimerTimeOut()
{
    IAM_LOGE("start");
    OnStop();
}

bool WidgetContext::GetRemoteAuthParam()
{
    IAM_LOGI("start");
    if (remoteAuthCallback_ == nullptr) {
        IAM_LOGE("remoteAuthCallback_ is nullptr");
        return false;
    }
    sptr<ISetWidgetParamCallback> setResultCallback =
        new (std::nothrow) SetWidgetParamCallbackService(contextId_);
    if (setResultCallback == nullptr) {
        IAM_LOGE("setResultCallback is nullptr");
        return false;
    }
    remoteAuthCallback_->OnGetRemoteAuthWidgetParam(para_.challenge, setResultCallback);
    StartRemoteAuthTimer();
    return true;
}

void WidgetContext::SetRemoteAuthParam(const WidgetParamInner &widgetParam, const sptr<IModalCallback> &modalCallback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    StopRemoteAuthTimer();
    para_.widgetParam = widgetParam;
    modalCallback_ = modalCallback;
    if (!schedule_->StartSchedule()) {
        IAM_LOGE("StartSchedule failed");
        return;
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
