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

#include "sudo_auth_context.h"

#include "auth_widget_helper.h"
#include "context_pool.h"
#include "context_arbitration_policy.h"
#include "iam_common_defines.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iiam_callback.h"
#include "simple_auth_context.h"
#include "widget_client.h"
#include "widget_context.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_SUDO_AUTH_CONTEXT

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class SudoChildCallbackImpl : public IIamCallback, public NoCopyable {
public:
    explicit SudoChildCallbackImpl(std::weak_ptr<SudoAuthContext> sudoContext) : sudoContext_(sudoContext)
    {
    }
    ~SudoChildCallbackImpl() override = default;

    int32_t OnResult(int32_t resultCode, const std::vector<uint8_t> &extraInfo) override
    {
        auto sudo = sudoContext_.lock();
        IF_FALSE_LOGE_AND_RETURN_VAL(sudo != nullptr, SUCCESS);
        Attributes finalResult(extraInfo);
        sudo->OnChildResult(resultCode, finalResult);
        return SUCCESS;
    }

    int32_t OnAcquireInfo(int32_t module, int32_t acquireInfo, const std::vector<uint8_t> &extraInfo) override
    {
        IAM_LOGD("acquire info dropped, module %{public}d acquireInfo %{public}d", module, acquireInfo);
        return SUCCESS;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }

private:
    std::weak_ptr<SudoAuthContext> sudoContext_;
};

SudoAuthContext::SudoAuthContext(uint64_t contextId, const ContextFactory::SudoAuthContextPara &para,
    std::shared_ptr<ContextCallback> callback)
    : BaseContext("SudoAuth", contextId, para.needSubscribeAppState, true, callback),
      para_(para)
{
}

ContextType SudoAuthContext::GetContextType() const
{
    return SUDO_AUTH_CONTEXT;
}

uint32_t SudoAuthContext::GetTokenId() const
{
    return para_.tokenId;
}

int32_t SudoAuthContext::GetUserId() const
{
    return para_.userId;
}

int32_t SudoAuthContext::GetAuthType() const
{
    return AuthType::PIN;
}

std::vector<int32_t> SudoAuthContext::GetAuthTypeList() const
{
    return {AuthType::PIN};
}

AuthIntent SudoAuthContext::GetAuthIntent() const
{
    return AuthIntent::SUDO_PIN_AUTH;
}

std::string SudoAuthContext::GetCallerName() const
{
    return para_.callerName;
}

bool SudoAuthContext::CanStart(const std::vector<std::weak_ptr<Context>> &predecessors) const
{
    return ContextAdmissionPolicy::CanStart(*this, predecessors);
}

PreemptDecision SudoAuthContext::GetPreemptDecision(const Context &newRequest) const
{
    if (!dialogActive_.load() || !newRequest.IsPrimaryContext()) {
        return PreemptDecision::KEEP_RUNNING;
    }
    ContextType newcomerType = newRequest.GetContextType();
    int32_t newcomerUserId = newRequest.GetUserId();
    bool newcomerTakesOverWindow = newcomerType == ContextType::SUDO_AUTH_CONTEXT ||
        newcomerType == ContextType::WIDGET_AUTH_CONTEXT;
    bool newcomerConflictsPinSlot = newcomerUserId != INVALID_USER_ID && newcomerUserId == para_.userId &&
        ContextAdmissionPolicy::IsAuthContext(newcomerType) && ContextAdmissionPolicy::BearsPin(newRequest);
    if (newcomerTakesOverWindow || newcomerConflictsPinSlot) {
        IAM_LOGI("sudo dialog ****%{public}hx yields to %{public}d newcomer ****%{public}hx",
            static_cast<uint16_t>(GetContextId()), static_cast<int32_t>(newcomerType),
            static_cast<uint16_t>(newRequest.GetContextId()));
        return PreemptDecision::STOP_NOW;
    }
    return PreemptDecision::KEEP_RUNNING;
}

std::shared_ptr<ContextCallback> SudoAuthContext::BuildChildCallback()
{
    std::weak_ptr<SudoAuthContext> weakThis(std::static_pointer_cast<SudoAuthContext>(shared_from_this()));
    sptr<IIamCallback> iamCallback(new (std::nothrow) SudoChildCallbackImpl(weakThis));
    IF_FALSE_LOGE_AND_RETURN_VAL(iamCallback != nullptr, nullptr);
    auto childCallback = ContextCallback::NewInstance(iamCallback, TRACE_AUTH_USER_SECURITY);
    IF_FALSE_LOGE_AND_RETURN_VAL(childCallback != nullptr, nullptr);
    childCallback->SetTraceCallerName(para_.callerName);
    childCallback->SetTraceCallerType(para_.callerType);
    childCallback->SetTraceRequestContextId(GetContextId());
    childCallback->SetTraceAuthTrustLevel(para_.atl);
    childCallback->SetTraceAuthType(AuthType::PIN);
    return childCallback;
}

bool SudoAuthContext::OnStart()
{
    IAM_LOGI("%{public}s start query", GetDescription());
    ContextFactory::AuthProfile profile = {};
    int32_t ret = AuthWidgetHelper::GetUserAuthProfile(para_.userId, AuthType::PIN, profile, {});
    if (ret == ResultCode::NOT_ENROLLED) {
        IAM_LOGI("%{public}s no pin credential", GetDescription());
        EndWithResult(ResultCode::NOT_ENROLLED, {});
        return true;
    }
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s query pin profile fail, fail-closed, ret: %{public}d, userId: %{public}d",
            GetDescription(), ret, para_.userId);
        EndWithResult(ResultCode::GENERAL_ERROR, {});
        return true;
    }
    IAM_LOGI("%{public}s query done, remain: %{public}d, freeze: %{public}d", GetDescription(), profile.remainTimes,
        profile.freezingTime);
    DispatchByProfile(profile);
    return true;
}

void SudoAuthContext::EndWithLocked(const ContextFactory::AuthProfile &profile)
{
    int32_t nextPhase = profile.nextPhaseFreezingTime > 0 ? profile.nextPhaseFreezingTime
                                                          : FIRST_LOCKOUT_DURATION_OF_PIN;
    Attributes lockedResult;
    lockedResult.SetInt32Value(Attributes::ATTR_RESULT_CODE, ResultCode::LOCKED);
    lockedResult.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 0);
    lockedResult.SetInt32Value(Attributes::ATTR_FREEZING_TIME, profile.freezingTime);
    lockedResult.SetInt32Value(Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION, nextPhase);
    EndWithResult(ResultCode::LOCKED, lockedResult);
}

void SudoAuthContext::DispatchByProfile(const ContextFactory::AuthProfile &profile)
{
    std::lock_guard<std::recursive_mutex> lock(sudoMutex_);
    if (phase_ != PHASE_QUERY) {
        IAM_LOGI("%{public}s profile dropped: context already past query", GetDescription());
        return;
    }
    if (profile.freezingTime > 0) {
        EndWithLocked(profile);
        return;
    }
    if (profile.remainTimes == 1) {
        childIsWidget_ = true;
        if (!StartWidgetChild(profile)) {
            childIsWidget_ = false;
            EndWithResult(ResultCode::GENERAL_ERROR, {});
        }
        return;
    }
    if (!StartSilentChild(profile)) {
        EndWithResult(ResultCode::GENERAL_ERROR, {});
    }
}

bool SudoAuthContext::StartSilentChild(const ContextFactory::AuthProfile &profile)
{
    auto childCallback = BuildChildCallback();
    IF_FALSE_LOGE_AND_RETURN_VAL(childCallback != nullptr, false);
    Authentication::AuthenticationPara para = {};
    para.tokenId = para_.tokenId;
    para.userId = para_.userId;
    para.authType = AuthType::PIN;
    para.atl = para_.atl;
    para.challenge = para_.challenge;
    para.endAfterFirstFail = true;
    para.callerName = para_.callerName;
    para.callerType = para_.callerType;
    para.sdkVersion = para_.sdkVersion;
    para.authIntent = AuthIntent::DEFAULT;
    para.isOsAccountVerified = para_.isOsAccountVerified;
    auto child = ContextFactory::CreateSimpleAuthContext(para, false, false, childCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(child != nullptr, false);
    childCallback->SetCleaner(ContextPool::Cleaner(child));
    return LaunchChild(child);
}

bool SudoAuthContext::StartWidgetChild(const ContextFactory::AuthProfile &profile)
{
    auto childCallback = BuildChildCallback();
    IF_FALSE_LOGE_AND_RETURN_VAL(childCallback != nullptr, false);
    ContextFactory::AuthWidgetContextPara para = {};
    para.isBackgroundApplication = !para_.needSubscribeAppState;
    para.userId = para_.userId;
    para.sdkVersion = para_.sdkVersion;
    para.isOsAccountVerified = para_.isOsAccountVerified;
    para.tokenId = para_.tokenId;
    para.callerName = para_.callerName;
    para.callerType = para_.callerType;
    para.challenge = para_.challenge;
    para.authTypeList = {AuthType::PIN};
    para.atl = para_.atl;
    para.widgetParam.title = para_.additionalInfo;
    para.widgetParam.windowMode = WindowModeType::DIALOG_BOX;
    para.authProfileMap[AuthType::PIN] = profile;
    auto child = ContextFactory::CreateWidgetContext(para, false, childCallback, nullptr, nullptr);
    IF_FALSE_LOGE_AND_RETURN_VAL(child != nullptr, false);
    dialogActive_.store(true);
    ContextPool::Instance().NotifyPreemptStateChanged();
    return LaunchChild(child);
}

bool SudoAuthContext::LaunchChild(const std::shared_ptr<Context> &child)
{
    childContextId_ = child->GetContextId();
    phase_ = PHASE_RUN;
    if (!ContextPool::Instance().Schedule(child)) {
        IAM_LOGE("%{public}s schedule child fail", GetDescription());
        return false;
    }
    return true;
}

void SudoAuthContext::OnChildResult(int32_t resultCode, const Attributes &finalResult)
{
    std::lock_guard<std::recursive_mutex> lock(sudoMutex_);
    if (phase_ != PHASE_RUN) {
        IAM_LOGI("%{public}s late child result ignored, result: %{public}d", GetDescription(), resultCode);
        return;
    }
    if (stopping_ || resultCode == ResultCode::CANCELED) {
        EndWithResult(ResultCode::CANCELED, finalResult);
        return;
    }
    if (resultCode == ResultCode::SUCCESS || !childIsWidget_) {
        EndWithResult(resultCode, finalResult);
        return;
    }
    ContextFactory::AuthProfile profile = {};
    int32_t ret = AuthWidgetHelper::GetUserAuthProfile(para_.userId, AuthType::PIN, profile, {});
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s requery pin profile fail, ret: %{public}d, userId: %{public}d", GetDescription(), ret,
            para_.userId);
    } else if (profile.freezingTime > 0) {
        EndWithLocked(profile);
        return;
    }
    EndWithResult(resultCode, finalResult);
}

bool SudoAuthContext::OnStop()
{
    uint64_t childId = 0;
    {
        std::lock_guard<std::recursive_mutex> lock(sudoMutex_);
        if (phase_ == PHASE_END) {
            return true;
        }
        if (phase_ != PHASE_RUN || !childContextId_.has_value()) {
            EndWithResult(ResultCode::CANCELED, {});
            return true;
        }
        stopping_ = true;
        childId = *childContextId_;
    }
    ContextPool::Instance().Cancel(childId);
    return true;
}

void SudoAuthContext::OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr)
{
    IAM_LOGD("%{public}s result %{public}d ignored", GetDescription(), resultCode);
}

void SudoAuthContext::EndWithResult(int32_t resultCode, const Attributes &finalResult)
{
    {
        std::lock_guard<std::recursive_mutex> lock(sudoMutex_);
        if (phase_ == PHASE_END) {
            return;
        }
        phase_ = PHASE_END;
        dialogActive_.store(false);
        childContextId_.reset();
    }
    IAM_LOGI("%{public}s end with result %{public}d", GetDescription(), resultCode);
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);
    callback_->OnResult(resultCode, finalResult);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
