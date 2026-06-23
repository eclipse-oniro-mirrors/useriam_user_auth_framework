/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#ifndef IAM_MOCK_IUSER_AUTH_INTERFACE_H
#define IAM_MOCK_IUSER_AUTH_INTERFACE_H

#include <memory>
#include <mutex>

#include "singleton.h"

#include "hdi_wrapper.h"
#include "user_auth_hdi.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockIUserAuthInterface final : public IUserAuthInterface {
public:
    class Holder;
    int32_t Init(const std::string &deviceUdid)
    {
        return 0;
    }

    int32_t AddExecutor(const HdiExecutorRegisterInfo &info, uint64_t &index,
        std::vector<uint8_t> &publicKey, std::vector<uint64_t> &templateIds)
    {
        return 0;
    }

    int32_t DeleteExecutor(uint64_t index)
    {
        return 0;
    }

    int32_t OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
    {
        return 0;
    }

    int32_t CloseSession(int32_t userId)
    {
        return 0;
    }

    int32_t UpdateEnrollmentResult(int32_t userId, const std::vector<uint8_t> &scheduleResult,
        HdiEnrollResultInfo &info)
    {
        return 0;
    }

    int32_t CancelEnrollment(int32_t userId)
    {
        return 0;
    }

    int32_t DeleteCredential(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
        HdiCredentialOperateResult &operateResult)
    {
        return 0;
    }

    int32_t GetCredential(int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos)
    {
        return 0;
    }

    int32_t GetUserInfo(int32_t userId, uint64_t &secureUid, int32_t &pinSubType, std::vector<HdiEnrolledInfo> &infos)
    {
        return 0;
    }

    int32_t DeleteUser(int32_t userId, const std::vector<uint8_t> &authToken,
        std::vector<HdiCredentialInfo> &deletedInfos, std::vector<uint8_t> &rootSecret)
    {
        return 0;
    }

    int32_t EnforceDeleteUser(int32_t userId, std::vector<HdiCredentialInfo> &deletedInfos)
    {
        return 0;
    }

    int32_t CancelAuthentication(uint64_t contextId)
    {
        return 0;
    }

    int32_t UpdateIdentificationResult(uint64_t contextId, const std::vector<uint8_t> &scheduleResult,
        HdiIdentifyResultInfo &info)
    {
        return 0;
    }

    int32_t CancelIdentification(uint64_t contextId)
    {
        return 0;
    }

    int32_t GetAvailableStatus(int32_t userId, int32_t authType, uint32_t authTrustLevel, int32_t &checkRet)
    {
        return 0;
    }

    int32_t GetValidSolution(int32_t userId, const std::vector<int32_t> &authTypes,
        uint32_t authTrustLevel, std::vector<int32_t> &validTypes)
    {
        return 0;
    }

    int32_t BeginIdentification(uint64_t contextId, int32_t authType, const std::vector<uint8_t> &challenge,
        uint32_t executorId, HdiScheduleInfo &scheduleInfo)
    {
        return 0;
    }

    int32_t GetAllUserInfo(std::vector<UserInfo> &userInfos)
    {
        return 0;
    }

    int32_t GetAllExtUserInfo(std::vector<ExtUserInfo> &userInfos)
    {
        return 0;
    }

    int32_t BeginEnrollment(const std::vector<uint8_t> &authToken, const HdiEnrollParam &param, HdiScheduleInfo &info)
    {
        return 0;
    }

    int32_t BeginEnrollmentExt(const std::vector<uint8_t> &authToken, const HdiEnrollParamExt &param,
        HdiScheduleInfo &info)
    {
        return 0;
    }

    int32_t BeginAuthentication(uint64_t contextId, const HdiAuthParam &param,
        std::vector<HdiScheduleInfo> &scheduleInfos)
    {
        return 0;
    }

    int32_t BeginAuthenticationExt(uint64_t contextId, const HdiAuthParamExt &param,
        std::vector<HdiScheduleInfo> &scheduleInfos)
    {
        static_cast<void>(contextId);
        static_cast<void>(param);
        static_cast<void>(scheduleInfos);
        return 0;
    }

    int32_t GetEnrolledState(int32_t userId, int32_t authType, HdiEnrolledState &hdiEnrolledState)
    {
        return 0;
    }

    int32_t UpdateAuthenticationResult(uint64_t contextId, const std::vector<uint8_t> &scheduleResult,
        HdiAuthResultInfo &info, HdiEnrolledState &enrolledState)
    {
        return 0;
    }

    int32_t CheckReuseUnlockResult(const HdiReuseUnlockParam &reuseParam, HdiReuseUnlockInfo &reuseInfo)
    {
        return 0;
    }

    int32_t SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg)
    {
        return 0;
    }

    int32_t RegisterMessageCallback(const sptr<HdiIMessageCallback> &messageCallback)
    {
        return 0;
    }

    int32_t PrepareRemoteAuth(const std::string &remoteUdid)
    {
        return 0;
    }

    int32_t GetLocalScheduleFromMessage(const std::string &remoteUdid, const std::vector<uint8_t> &message,
        HdiScheduleInfo &scheduleInfo)
    {
        return 0;
    }

    int32_t GetSignedExecutorInfo(const std::vector<int32_t> &authTypes, int32_t executorRole,
        const std::string &remoteUdid, std::vector<uint8_t> &signedExecutorInfo)
    {
        return 0;
    }

    int32_t SetGlobalConfigParam(const HdiGlobalConfigParam &param)
    {
        return 0;
    }

    int32_t GetAuthResultFromMessage(const std::string &remoteUdid, const std::vector<uint8_t> &message,
        HdiAuthResultInfo &authResultInfo)
    {
        return 0;
    }

    int32_t VerifyAuthToken(const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
        HdiUserAuthTokenPlain &tokenPlainOut, std::vector<uint8_t> &rootSecret)
    {
        return 0;
    }

    int32_t GetCredentialById(uint64_t credentialId, HdiCredentialInfo &info)
    {
        return 0;
    }

    int32_t UpdateAbandonResult(int32_t userId, const std::vector<uint8_t> &scheduleResult,
        std::vector<HdiCredentialInfo> &infos)
    {
        return 0;
    }

    int32_t ClearUnavailableCredential(const std::vector<int32_t> &userIds,
        std::vector<HdiCredentialInfo> &infos)
    {
        return 0;
    }
};

class MockIUserAuthInterface::Holder : public Singleton<MockIUserAuthInterface::Holder> {
public:
    void Reset();
    std::shared_ptr<MockIUserAuthInterface> Get();

private:
    std::mutex mutex_;
    std::weak_ptr<MockIUserAuthInterface> mock_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_IUSER_AUTH_INTERFACE_H