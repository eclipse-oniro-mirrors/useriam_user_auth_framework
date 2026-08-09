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

#ifndef HDI_ENGINE_H
#define HDI_ENGINE_H

#include <mutex>

#include "iservstat_listener_hdi.h"
#include "system_ability_listener.h"
#include "hdi_type_aliases.h"
#include "user_auth_engine.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using EngineMessageCallback = IMessageCallback;

class HdiMessageCallbackBridge : public HdiIMessageCallback {
public:
    explicit HdiMessageCallbackBridge(sptr<EngineMessageCallback> delegate);
    ~HdiMessageCallbackBridge() override = default;

    int32_t OnMessage(uint64_t scheduleId, int32_t destRole, const std::vector<uint8_t> &msg) override;

private:
    sptr<EngineMessageCallback> delegate_;
};

class HdiEngineImpl : public IUserAuthEngine {
public:
    HdiEngineImpl();
    ~HdiEngineImpl() override;

    int32_t Init(const std::string &deviceUdid) override;
    int32_t AddExecutor(const CoAuthInterface::ExecutorRegisterInfo &info, uint64_t &index,
        std::vector<uint8_t> &publicKey, std::vector<uint64_t> &templateIds) override;
    int32_t DeleteExecutor(uint64_t index) override;
    int32_t OpenSession(int32_t userId, std::vector<uint8_t> &challenge) override;
    int32_t CloseSession(int32_t userId) override;
    int32_t BeginEnrollment(const std::vector<uint8_t> &authToken, const EngEnrollParam &param,
        EngScheduleInfo &info) override;
    int32_t UpdateEnrollmentResult(int32_t userId, const std::vector<uint8_t> &scheduleResult,
        EngEnrollResultInfo &info) override;
    int32_t CancelEnrollment(int32_t userId) override;
    int32_t BeginAuthentication(uint64_t contextId, const EngAuthParam &param,
        std::vector<EngScheduleInfo> &scheduleInfos) override;
    int32_t UpdateAuthenticationResult(uint64_t contextId, const std::vector<uint8_t> &scheduleResult,
        EngAuthResultInfo &info, EngEnrolledState &enrolledState) override;
    int32_t CancelAuthentication(uint64_t contextId) override;
    int32_t GetCredential(int32_t userId, int32_t authType, std::vector<EngCredentialInfo> &infos) override;
    int32_t DeleteCredential(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
        EngCredentialOperateResult &operateResult) override;
    int32_t GetAvailableStatus(int32_t userId, int32_t authType, uint32_t authTrustLevel,
        int32_t &checkResult) override;
    int32_t GetUserInfo(int32_t userId, uint64_t &secureUid, int32_t &pinSubType,
        std::vector<EnrolledInfo> &infos) override;
    int32_t DeleteUser(int32_t userId, const std::vector<uint8_t> &authToken,
        std::vector<EngCredentialInfo> &deletedInfos, std::vector<uint8_t> &rootSecret) override;
    int32_t EnforceDeleteUser(int32_t userId, std::vector<EngCredentialInfo> &deletedInfos) override;
    int32_t GetAllExtUserInfo(std::vector<EngExtUserInfo> &userInfos) override;
    int32_t GetCredentialById(uint64_t credentialId, EngCredentialInfo &info) override;
    int32_t ClearUnavailableCredential(const std::vector<int32_t> &userIds,
        std::vector<EngCredentialInfo> &infos) override;
    int32_t UpdateAbandonResult(int32_t userId, const std::vector<uint8_t> &scheduleResult,
        std::vector<EngCredentialInfo> &infos) override;
    int32_t BeginIdentification(uint64_t contextId, int32_t authType, const std::vector<uint8_t> &challenge,
        uint32_t executorSensorHint, EngScheduleInfo &scheduleInfo) override;
    int32_t UpdateIdentificationResult(uint64_t contextId, const std::vector<uint8_t> &scheduleResult,
        EngIdentifyResultInfo &info) override;
    int32_t CancelIdentification(uint64_t contextId) override;
    int32_t BeginEnrollmentExt(const std::vector<uint8_t> &authToken, const EngEnrollParamExt &param,
        EngScheduleInfo &info) override;
    int32_t BeginAuthenticationExt(uint64_t contextId, const EngAuthParamExt &param,
        std::vector<EngScheduleInfo> &scheduleInfos) override;
    int32_t SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg) override;
    int32_t GetSignedExecutorInfo(const std::vector<int32_t> &authTypes, int32_t executorRole,
        const std::string &remoteUdid, std::vector<uint8_t> &signedExecutorInfo) override;
    int32_t PrepareRemoteAuth(const std::string &remoteUdid) override;
    int32_t GetEnrolledState(int32_t userId, int32_t authType, EngEnrolledState &enrolledState) override;
    int32_t SetGlobalConfigParam(const EngGlobalConfigParam &param) override;
    int32_t VerifyAuthToken(const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
        EngUserAuthTokenPlain &tokenPlainOut, std::vector<uint8_t> &rootSecret) override;
    int32_t RegisterMessageCallback(const sptr<IMessageCallback> &messageCallback) override;
    int32_t GetValidSolution(int32_t userId, const std::vector<int32_t> &authTypes, uint32_t authTrustLevel,
        std::vector<int32_t> &validTypes) override;
    int32_t CheckReuseUnlockResult(const EngReuseUnlockParam &reuseParam, EngReuseUnlockInfo &reuseInfo) override;
    int32_t GetLocalScheduleFromMessage(const std::string &remoteUdid, const std::vector<uint8_t> &message,
        EngScheduleInfo &scheduleInfo) override;
    int32_t GetAuthResultFromMessage(const std::string &remoteUdid, const std::vector<uint8_t> &message,
        EngAuthResultInfo &authResultInfo) override;
    bool SetStatusCallback(const StateCallback &callback) override;
    int32_t Load() override;
    int32_t Unload() override;
    std::string GetType() const override;
    bool IsWidgetCallerAllowedOnLockScreen(const EngCallerAuthInfo &callerInfo) const override;

    void OnDriverManagerAdd();
    void OnDriverManagerRemove();
    void NotifyDriverState(bool running);

private:
    std::recursive_mutex mutex_;
    StateCallback stateCallback_;
    sptr<SystemAbilityListener> driverManagerListener_ = nullptr;
    sptr<HDI::ServiceManager::V1_0::ServStatListenerStub> driverStatusListener_ = nullptr;
    sptr<HdiMessageCallbackBridge> messageCallbackBridge_ = nullptr;

    void OnDriverState(bool running);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // HDI_ENGINE_H
