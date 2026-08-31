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

#include "hdi_engine.h"

#include "hdi_type_aliases.h"
#include "hdi_type_convert.h"
#include "hdi_wrapper.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "idevmgr_hdi.h"
#include "iservmgr_hdi.h"
#include "system_ability_definition.h"
#include "thread_handler.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_HDI_ENGINE

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
using namespace HDI;
using namespace HDI::ServiceManager::V1_0;
const char *SERVICE_NAME = "user_auth_interface_service";

class DriverStatusListener : public ServStatListenerStub {
public:
    explicit DriverStatusListener(HdiEngineImpl *owner) : owner_(owner)
    {
    }
    ~DriverStatusListener() override = default;

    void OnReceive(const ServiceStatus &status) override
    {
        if (status.serviceName != SERVICE_NAME) {
            return;
        }
        IAM_LOGI("receive service %{public}s status %{public}u", status.serviceName.c_str(), status.status);
        IF_FALSE_LOGE_AND_RETURN(owner_ != nullptr);
        if (status.status == SERVIE_STATUS_START) {
            owner_->NotifyDriverState(true);
        } else if (status.status == SERVIE_STATUS_STOP) {
            owner_->NotifyDriverState(false);
        }
    }

private:
    HdiEngineImpl *owner_ { nullptr };
};
} // namespace

HdiMessageCallbackBridge::HdiMessageCallbackBridge(sptr<EngineMessageCallback> delegate)
    : delegate_(std::move(delegate))
{
}

int32_t HdiMessageCallbackBridge::OnMessage(uint64_t scheduleId, int32_t destRole, const std::vector<uint8_t> &msg)
{
    if (delegate_ == nullptr) {
        IAM_LOGE("delegate is nullptr");
        return HDF_FAILURE;
    }
    int32_t ret = delegate_->OnMessage(scheduleId, destRole, msg);
    return (ret == SUCCESS) ? HDF_SUCCESS : HDF_FAILURE;
}

HdiEngineImpl::HdiEngineImpl()
{
}

HdiEngineImpl::~HdiEngineImpl()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (driverStatusListener_ != nullptr) {
        auto servMgr = IServiceManager::Get();
        if (servMgr != nullptr) {
            (void)servMgr->UnregisterServiceStatusListener(driverStatusListener_);
        }
    }
    if (driverManagerListener_ != nullptr) {
        (void)SystemAbilityListener::UnSubscribe(DEVICE_SERVICE_MANAGER_SA_ID, driverManagerListener_);
    }
}

IUserAuthEngine &GetUserAuthEngine()
{
    static HdiEngineImpl instance;
    return instance;
}

int32_t HdiEngineImpl::Init(const std::string &deviceUdid)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    return HdfCodeToResult(hdi->Init(deviceUdid));
}

int32_t HdiEngineImpl::AddExecutor(const CoAuthInterface::ExecutorRegisterInfo &info, uint64_t &index,
    std::vector<uint8_t> &publicKey, std::vector<uint64_t> &templateIds)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    return HdfCodeToResult(hdi->AddExecutor(EngToHdi(info), index, publicKey, templateIds));
}

int32_t HdiEngineImpl::DeleteExecutor(uint64_t index)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    return HdfCodeToResult(hdi->DeleteExecutor(index));
}

int32_t HdiEngineImpl::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    return HdfCodeToResult(hdi->OpenSession(userId, challenge));
}

int32_t HdiEngineImpl::CloseSession(int32_t userId)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    return HdfCodeToResult(hdi->CloseSession(userId));
}

int32_t HdiEngineImpl::BeginEnrollment(const std::vector<uint8_t> &authToken, const EngEnrollParam &param,
    EngScheduleInfo &info)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    HdiScheduleInfo hdiInfo;
    int32_t ret = hdi->BeginEnrollment(authToken, EngToHdi(param), hdiInfo);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    info = HdiToEng(hdiInfo);
    return SUCCESS;
}

int32_t HdiEngineImpl::UpdateEnrollmentResult(int32_t userId, const std::vector<uint8_t> &scheduleResult,
    EngEnrollResultInfo &info)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    HdiEnrollResultInfo hdiInfo;
    int32_t ret = hdi->UpdateEnrollmentResult(userId, scheduleResult, hdiInfo);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    info = HdiToEng(hdiInfo);
    return SUCCESS;
}

int32_t HdiEngineImpl::CancelEnrollment(int32_t userId)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    return HdfCodeToResult(hdi->CancelEnrollment(userId));
}

int32_t HdiEngineImpl::BeginAuthentication(uint64_t contextId, const EngAuthParam &param,
    std::vector<EngScheduleInfo> &scheduleInfos)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    std::vector<HdiScheduleInfo> hdiScheduleInfos;
    int32_t ret = hdi->BeginAuthentication(contextId, EngToHdi(param), hdiScheduleInfos);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    scheduleInfos = VecHdiToEng<EngScheduleInfo, HdiScheduleInfo>(hdiScheduleInfos);
    return SUCCESS;
}

int32_t HdiEngineImpl::UpdateAuthenticationResult(uint64_t contextId, const std::vector<uint8_t> &scheduleResult,
    EngAuthResultInfo &info, EngEnrolledState &enrolledState)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    HdiAuthResultInfo hdiInfo;
    HdiEnrolledState hdiEnrolledState;
    int32_t ret = hdi->UpdateAuthenticationResult(contextId, scheduleResult, hdiInfo, hdiEnrolledState);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    info = HdiToEng(hdiInfo);
    enrolledState = HdiToEng(hdiEnrolledState);
    return SUCCESS;
}

int32_t HdiEngineImpl::CancelAuthentication(uint64_t contextId)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    return HdfCodeToResult(hdi->CancelAuthentication(contextId));
}

int32_t HdiEngineImpl::GetCredential(int32_t userId, int32_t authType, std::vector<EngCredentialInfo> &infos)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    std::vector<HdiCredentialInfo> hdiInfos;
    int32_t ret = hdi->GetCredential(userId, authType, hdiInfos);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    infos = VecHdiToEng<EngCredentialInfo, HdiCredentialInfo>(hdiInfos);
    return SUCCESS;
}

int32_t HdiEngineImpl::DeleteCredential(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
    EngCredentialOperateResult &operateResult)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    HdiCredentialOperateResult hdiOperateResult;
    int32_t ret = hdi->DeleteCredential(userId, credentialId, authToken, hdiOperateResult);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    operateResult = HdiToEng(hdiOperateResult);
    return SUCCESS;
}

int32_t HdiEngineImpl::GetAvailableStatus(int32_t userId, int32_t authType, uint32_t authTrustLevel,
    int32_t &checkResult)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    return HdfCodeToResult(hdi->GetAvailableStatus(userId, authType, authTrustLevel, checkResult));
}

int32_t HdiEngineImpl::GetUserInfo(int32_t userId, uint64_t &secureUid, int32_t &pinSubType,
    std::vector<EnrolledInfo> &infos)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    std::vector<HdiEnrolledInfo> hdiInfos;
    int32_t ret = hdi->GetUserInfo(userId, secureUid, pinSubType, hdiInfos);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    infos = VecHdiToEng<EnrolledInfo, HdiEnrolledInfo>(hdiInfos);
    return SUCCESS;
}

int32_t HdiEngineImpl::DeleteUser(int32_t userId, const std::vector<uint8_t> &authToken,
    std::vector<EngCredentialInfo> &deletedInfos, std::vector<uint8_t> &rootSecret)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    std::vector<HdiCredentialInfo> hdiDeletedInfos;
    int32_t ret = hdi->DeleteUser(userId, authToken, hdiDeletedInfos, rootSecret);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    deletedInfos = VecHdiToEng<EngCredentialInfo, HdiCredentialInfo>(hdiDeletedInfos);
    return SUCCESS;
}

int32_t HdiEngineImpl::EnforceDeleteUser(int32_t userId, std::vector<EngCredentialInfo> &deletedInfos)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    std::vector<HdiCredentialInfo> hdiDeletedInfos;
    int32_t ret = hdi->EnforceDeleteUser(userId, hdiDeletedInfos);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    deletedInfos = VecHdiToEng<EngCredentialInfo, HdiCredentialInfo>(hdiDeletedInfos);
    return SUCCESS;
}

int32_t HdiEngineImpl::DeleteSubProfile(int32_t subProfileId, std::vector<EngCredentialInfo> &deletedInfos)
{
    IAM_LOGI("start, subProfileId:%{public}d", subProfileId);
    return SUCCESS;
}

int32_t HdiEngineImpl::GetAllExtUserInfo(std::vector<EngExtUserInfo> &userInfos)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    std::vector<HdiExtUserInfo> hdiUserInfos;
    int32_t ret = hdi->GetAllExtUserInfo(hdiUserInfos);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    userInfos = VecHdiToEng<EngExtUserInfo, HdiExtUserInfo>(hdiUserInfos);
    return SUCCESS;
}

int32_t HdiEngineImpl::GetCredentialById(uint64_t credentialId, EngCredentialInfo &info)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    HdiCredentialInfo hdiInfo;
    int32_t ret = hdi->GetCredentialById(credentialId, hdiInfo);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    info = HdiToEng(hdiInfo);
    return SUCCESS;
}

int32_t HdiEngineImpl::ClearUnavailableCredential(const std::vector<int32_t> &userIds,
    std::vector<EngCredentialInfo> &infos)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    std::vector<HdiCredentialInfo> hdiInfos;
    int32_t ret = hdi->ClearUnavailableCredential(userIds, hdiInfos);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    infos = VecHdiToEng<EngCredentialInfo, HdiCredentialInfo>(hdiInfos);
    return SUCCESS;
}

int32_t HdiEngineImpl::UpdateAbandonResult(int32_t userId, const std::vector<uint8_t> &scheduleResult,
    std::vector<EngCredentialInfo> &infos)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    std::vector<HdiCredentialInfo> hdiInfos;
    int32_t ret = hdi->UpdateAbandonResult(userId, scheduleResult, hdiInfos);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    infos = VecHdiToEng<EngCredentialInfo, HdiCredentialInfo>(hdiInfos);
    return SUCCESS;
}

int32_t HdiEngineImpl::BeginIdentification(uint64_t contextId, int32_t authType, const std::vector<uint8_t> &challenge,
    uint32_t executorSensorHint, EngScheduleInfo &scheduleInfo)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    HdiScheduleInfo hdiScheduleInfo;
    int32_t ret = hdi->BeginIdentification(contextId, authType, challenge, executorSensorHint, hdiScheduleInfo);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    scheduleInfo = HdiToEng(hdiScheduleInfo);
    return SUCCESS;
}

int32_t HdiEngineImpl::UpdateIdentificationResult(uint64_t contextId, const std::vector<uint8_t> &scheduleResult,
    EngIdentifyResultInfo &info)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    HdiIdentifyResultInfo hdiInfo;
    int32_t ret = hdi->UpdateIdentificationResult(contextId, scheduleResult, hdiInfo);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    info = HdiToEng(hdiInfo);
    return SUCCESS;
}

int32_t HdiEngineImpl::CancelIdentification(uint64_t contextId)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    return HdfCodeToResult(hdi->CancelIdentification(contextId));
}

int32_t HdiEngineImpl::BeginEnrollmentExt(const std::vector<uint8_t> &authToken, const EngEnrollParamExt &param,
    EngScheduleInfo &info)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    HdiScheduleInfo hdiInfo;
    int32_t ret = hdi->BeginEnrollmentExt(authToken, EngToHdi(param), hdiInfo);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    info = HdiToEng(hdiInfo);
    return SUCCESS;
}

int32_t HdiEngineImpl::BeginAuthenticationExt(uint64_t contextId, EngAuthParamExt &param,
    std::vector<EngScheduleInfo> &scheduleInfos)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    std::vector<HdiScheduleInfo> hdiScheduleInfos;
    int32_t ret = hdi->BeginAuthenticationExt(contextId, EngToHdi(param), hdiScheduleInfos);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    scheduleInfos = VecHdiToEng<EngScheduleInfo, HdiScheduleInfo>(hdiScheduleInfos);
    return SUCCESS;
}

int32_t HdiEngineImpl::SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    return HdfCodeToResult(hdi->SendMessage(scheduleId, srcRole, msg));
}

int32_t HdiEngineImpl::GetSignedExecutorInfo(const std::vector<int32_t> &authTypes, int32_t executorRole,
    const std::string &remoteUdid, std::vector<uint8_t> &signedExecutorInfo)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    return HdfCodeToResult(hdi->GetSignedExecutorInfo(authTypes, executorRole, remoteUdid, signedExecutorInfo));
}

int32_t HdiEngineImpl::PrepareRemoteAuth(const std::string &remoteUdid)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    return HdfCodeToResult(hdi->PrepareRemoteAuth(remoteUdid));
}

int32_t HdiEngineImpl::GetEnrolledState(int32_t userId, int32_t authType, EngEnrolledState &enrolledState)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    HdiEnrolledState hdiEnrolledState;
    int32_t ret = hdi->GetEnrolledState(userId, authType, hdiEnrolledState);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    enrolledState = HdiToEng(hdiEnrolledState);
    return SUCCESS;
}

int32_t HdiEngineImpl::SetGlobalConfigParam(const EngGlobalConfigParam &param)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    return HdfCodeToResult(hdi->SetGlobalConfigParam(EngToHdi(param)));
}

int32_t HdiEngineImpl::VerifyAuthToken(const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
    EngUserAuthTokenPlain &tokenPlainOut, std::vector<uint8_t> &rootSecret)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    HdiUserAuthTokenPlain hdiTokenPlainOut;
    int32_t ret = hdi->VerifyAuthToken(tokenIn, allowableDuration, hdiTokenPlainOut, rootSecret);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    tokenPlainOut = HdiToEng(hdiTokenPlainOut);
    return SUCCESS;
}

int32_t HdiEngineImpl::RegisterMessageCallback(const sptr<IMessageCallback> &messageCallback)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IF_FALSE_LOGE_AND_RETURN_VAL(messageCallback != nullptr, INVALID_PARAMETERS);
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    messageCallbackBridge_ = new (std::nothrow) HdiMessageCallbackBridge(messageCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(messageCallbackBridge_ != nullptr, HdfCodeToResult(HDF_FAILURE));
    return HdfCodeToResult(hdi->RegisterMessageCallback(messageCallbackBridge_));
}

int32_t HdiEngineImpl::GetValidSolution(int32_t userId, const std::vector<int32_t> &authTypes, uint32_t authTrustLevel,
    std::vector<int32_t> &validTypes)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    return HdfCodeToResult(hdi->GetValidSolution(userId, authTypes, authTrustLevel, validTypes));
}

int32_t HdiEngineImpl::CheckReuseUnlockResult(const EngReuseUnlockParam &reuseParam, EngReuseUnlockInfo &reuseInfo)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    HdiReuseUnlockInfo hdiReuseInfo;
    int32_t ret = hdi->CheckReuseUnlockResult(EngToHdi(reuseParam), hdiReuseInfo);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    reuseInfo = HdiToEng(hdiReuseInfo);
    return SUCCESS;
}

int32_t HdiEngineImpl::GetLocalScheduleFromMessage(const std::string &remoteUdid, const std::vector<uint8_t> &message,
    EngScheduleInfo &scheduleInfo)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    HdiScheduleInfo hdiScheduleInfo;
    int32_t ret = hdi->GetLocalScheduleFromMessage(remoteUdid, message, hdiScheduleInfo);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    scheduleInfo = HdiToEng(hdiScheduleInfo);
    return SUCCESS;
}

int32_t HdiEngineImpl::GetAuthResultFromMessage(const std::string &remoteUdid, const std::vector<uint8_t> &message,
    EngAuthResultInfo &authResultInfo)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ENGINE_UNAVAILABLE);
    HdiAuthResultInfo hdiAuthResultInfo;
    int32_t ret = hdi->GetAuthResultFromMessage(remoteUdid, message, hdiAuthResultInfo);
    if (ret != HDF_SUCCESS) {
        return HdfCodeToResult(ret);
    }
    authResultInfo = HdiToEng(hdiAuthResultInfo);
    return SUCCESS;
}

int32_t HdiEngineImpl::Load()
{
    auto devMgr = HDI::DeviceManager::V1_0::IDeviceManager::Get();
    IF_FALSE_LOGE_AND_RETURN_VAL(devMgr != nullptr, ENGINE_UNAVAILABLE);
    return HdfCodeToResult(devMgr->LoadDevice(SERVICE_NAME));
}

int32_t HdiEngineImpl::Unload()
{
    auto devMgr = HDI::DeviceManager::V1_0::IDeviceManager::Get();
    IF_FALSE_LOGE_AND_RETURN_VAL(devMgr != nullptr, ENGINE_UNAVAILABLE);
    return HdfCodeToResult(devMgr->UnloadDevice(SERVICE_NAME));
}

std::string HdiEngineImpl::GetType() const
{
    return SERVICE_NAME;
}

bool HdiEngineImpl::IsWidgetCallerAllowedOnLockScreen(const EngCallerAuthInfo &callerInfo) const
{
    IAM_LOGI("widget lock-screen launch denied by default, caller %{public}s", callerInfo.callerName.c_str());
    return false;
}

bool HdiEngineImpl::SetStatusCallback(const StateCallback &callback)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    stateCallback_ = callback;

    if (driverStatusListener_ == nullptr) {
        driverStatusListener_ = new (std::nothrow) DriverStatusListener(this);
        if (driverStatusListener_ == nullptr) {
            IAM_LOGE("create driver status listener failed");
            return false;
        }
    }

    if (driverManagerListener_ == nullptr) {
        driverManagerListener_ = SystemAbilityListener::Subscribe(
            "DriverManager", DEVICE_SERVICE_MANAGER_SA_ID, [this]() { OnDriverManagerAdd(); },
            [this]() { OnDriverManagerRemove(); });
        if (driverManagerListener_ == nullptr) {
            IAM_LOGE("subscribe driver manager listener failed");
            return false;
        }
    }
    return true;
}

void HdiEngineImpl::OnDriverManagerAdd()
{
    bool alreadyRunning = false;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        IAM_LOGI("driver manager add");
        IF_FALSE_LOGE_AND_RETURN(driverStatusListener_ != nullptr);

        auto servMgr = IServiceManager::Get();
        IF_FALSE_LOGE_AND_RETURN(servMgr != nullptr);

        (void)servMgr->UnregisterServiceStatusListener(driverStatusListener_);
        int32_t ret = servMgr->RegisterServiceStatusListener(driverStatusListener_, DEVICE_CLASS_USERAUTH);
        if (ret != 0) {
            IAM_LOGE("RegisterServiceStatusListener failed ret %{public}d", ret);
            return;
        }

        auto service = servMgr->GetService(SERVICE_NAME);
        alreadyRunning = (service != nullptr);
    }
    NotifyDriverState(alreadyRunning);
}

void HdiEngineImpl::OnDriverManagerRemove()
{
    IAM_LOGI("driver manager remove");
    NotifyDriverState(false);
}

void HdiEngineImpl::NotifyDriverState(bool running)
{
    // Serialize through the single handler thread: the snapshot and live events deliver in enqueue order.
    auto handler = ThreadHandler::GetSingleThreadInstance();
    IF_FALSE_LOGE_AND_RETURN(handler != nullptr);
    handler->PostTask([this, running]() { OnDriverState(running); });
}

void HdiEngineImpl::OnDriverState(bool running)
{
    StateCallback cb;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        cb = stateCallback_;
    }
    if (cb != nullptr) {
        cb(running);
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
