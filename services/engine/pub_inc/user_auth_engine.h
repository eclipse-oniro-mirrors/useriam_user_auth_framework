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

#ifndef USER_AUTH_ENGINE_H
#define USER_AUTH_ENGINE_H

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "refbase.h"
#include "user_auth_engine_types.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IMessageCallback : public virtual RefBase {
public:
    virtual ~IMessageCallback() = default;
    virtual int32_t OnMessage(uint64_t scheduleId, int32_t destRole, const std::vector<uint8_t> &msg) = 0;
};

enum EngineCapability : uint32_t {
    SUPPORT_USER_RECOGNITION = 1 << 0,
};

class IUserAuthEngine {
public:
    virtual ~IUserAuthEngine() = default;

    virtual int32_t Init(const std::string &deviceUdid) = 0;
    virtual int32_t AddExecutor(const CoAuthInterface::ExecutorRegisterInfo &info, uint64_t &index,
        std::vector<uint8_t> &publicKey, std::vector<uint64_t> &templateIds) = 0;
    virtual int32_t DeleteExecutor(uint64_t index) = 0;
    virtual int32_t OpenSession(int32_t userId, std::vector<uint8_t> &challenge) = 0;
    virtual int32_t CloseSession(int32_t userId) = 0;
    virtual int32_t BeginEnrollment(const std::vector<uint8_t> &authToken, const EngEnrollParam &param,
        EngScheduleInfo &info) = 0;
    virtual int32_t UpdateEnrollmentResult(int32_t userId, const std::vector<uint8_t> &scheduleResult,
        EngEnrollResultInfo &info) = 0;
    virtual int32_t CancelEnrollment(int32_t userId) = 0;
    virtual int32_t BeginAuthentication(uint64_t contextId, const EngAuthParam &param,
        std::vector<EngScheduleInfo> &scheduleInfos) = 0;
    virtual int32_t UpdateAuthenticationResult(uint64_t contextId, const std::vector<uint8_t> &scheduleResult,
        EngAuthResultInfo &info, EngEnrolledState &enrolledState) = 0;
    virtual int32_t CancelAuthentication(uint64_t contextId) = 0;
    virtual int32_t GetCredential(int32_t userId, int32_t authType, std::vector<EngCredentialInfo> &infos) = 0;
    virtual int32_t DeleteCredential(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
        EngCredentialOperateResult &operateResult) = 0;
    virtual int32_t GetAvailableStatus(int32_t userId, int32_t authType, uint32_t authTrustLevel,
        int32_t &checkResult) = 0;
    virtual int32_t GetUserInfo(int32_t userId, uint64_t &secureUid, int32_t &pinSubType,
        std::vector<EnrolledInfo> &infos) = 0;
    virtual int32_t DeleteUser(int32_t userId, const std::vector<uint8_t> &authToken,
        std::vector<EngCredentialInfo> &deletedInfos, std::vector<uint8_t> &rootSecret) = 0;
    virtual int32_t EnforceDeleteUser(int32_t userId, std::vector<EngCredentialInfo> &deletedInfos) = 0;
    virtual int32_t GetAllExtUserInfo(std::vector<EngExtUserInfo> &userInfos) = 0;
    virtual int32_t GetCredentialById(uint64_t credentialId, EngCredentialInfo &info) = 0;
    virtual int32_t ClearUnavailableCredential(const std::vector<int32_t> &userIds,
        std::vector<EngCredentialInfo> &infos) = 0;
    virtual int32_t UpdateAbandonResult(int32_t userId, const std::vector<uint8_t> &scheduleResult,
        std::vector<EngCredentialInfo> &infos) = 0;
    virtual int32_t BeginIdentification(uint64_t contextId, int32_t authType, const std::vector<uint8_t> &challenge,
        uint32_t executorSensorHint, EngScheduleInfo &scheduleInfo) = 0;
    virtual int32_t UpdateIdentificationResult(uint64_t contextId, const std::vector<uint8_t> &scheduleResult,
        EngIdentifyResultInfo &info) = 0;
    virtual int32_t CancelIdentification(uint64_t contextId) = 0;
    virtual int32_t BeginEnrollmentExt(const std::vector<uint8_t> &authToken, const EngEnrollParamExt &param,
        EngScheduleInfo &info) = 0;
    virtual int32_t BeginAuthenticationExt(uint64_t contextId, const EngAuthParamExt &param,
        std::vector<EngScheduleInfo> &scheduleInfos) = 0;
    virtual int32_t SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg) = 0;
    virtual int32_t GetSignedExecutorInfo(const std::vector<int32_t> &authTypes, int32_t executorRole,
        const std::string &remoteUdid, std::vector<uint8_t> &signedExecutorInfo) = 0;
    virtual int32_t PrepareRemoteAuth(const std::string &remoteUdid) = 0;
    virtual int32_t GetEnrolledState(int32_t userId, int32_t authType, EngEnrolledState &enrolledState) = 0;
    virtual int32_t SetGlobalConfigParam(const EngGlobalConfigParam &param) = 0;
    virtual int32_t VerifyAuthToken(const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
        EngUserAuthTokenPlain &tokenPlainOut, std::vector<uint8_t> &rootSecret) = 0;
    virtual int32_t RegisterMessageCallback(const sptr<IMessageCallback> &messageCallback) = 0;
    virtual int32_t GetValidSolution(int32_t userId, const std::vector<int32_t> &authTypes, uint32_t authTrustLevel,
        std::vector<int32_t> &validTypes) = 0;
    virtual int32_t CheckReuseUnlockResult(const EngReuseUnlockParam &reuseParam, EngReuseUnlockInfo &reuseInfo) = 0;
    virtual int32_t GetLocalScheduleFromMessage(const std::string &remoteUdid, const std::vector<uint8_t> &message,
        EngScheduleInfo &scheduleInfo) = 0;
    virtual int32_t GetAuthResultFromMessage(const std::string &remoteUdid, const std::vector<uint8_t> &message,
        EngAuthResultInfo &authResultInfo) = 0;

    using StateCallback = std::function<void(bool running)>;
    virtual bool SetStatusCallback(const StateCallback &callback) = 0;

    virtual int32_t Load() = 0;
    virtual int32_t Unload() = 0;

    virtual std::string GetType() const
    {
        return {};
    }

    virtual bool IsWidgetCallerAllowedOnLockScreen(const EngCallerAuthInfo &callerInfo) const = 0;

    virtual uint32_t GetCapability() const
    {
        return 0;
    }
};

IUserAuthEngine &GetUserAuthEngine();
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_ENGINE_H
