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
#ifndef IAM_DUMMY_USER_AUTH_ENGINE_H
#define IAM_DUMMY_USER_AUTH_ENGINE_H

#include "user_auth_engine.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
// Stateless engine used by the business fuzzers: the fuzz targets exercise the
// service/core/context code paths, so a no-op engine is enough and keeps the
// targets free of the HDI headers.
class DummyUserAuthEngine final : public IUserAuthEngine {
public:
    int32_t Init(const std::string &) override
    {
        return SUCCESS;
    }

    int32_t AddExecutor(const CoAuthInterface::ExecutorRegisterInfo &, uint64_t &, std::vector<uint8_t> &,
        std::vector<uint64_t> &) override
    {
        return SUCCESS;
    }

    int32_t DeleteExecutor(uint64_t) override
    {
        return SUCCESS;
    }

    int32_t OpenSession(int32_t, std::vector<uint8_t> &) override
    {
        return SUCCESS;
    }

    int32_t CloseSession(int32_t) override
    {
        return SUCCESS;
    }

    int32_t BeginEnrollment(const std::vector<uint8_t> &, const EngEnrollParam &, EngScheduleInfo &) override
    {
        return SUCCESS;
    }

    int32_t UpdateEnrollmentResult(int32_t, const std::vector<uint8_t> &, EngEnrollResultInfo &) override
    {
        return SUCCESS;
    }

    int32_t CancelEnrollment(int32_t) override
    {
        return SUCCESS;
    }

    int32_t BeginAuthentication(uint64_t, const EngAuthParam &, std::vector<EngScheduleInfo> &) override
    {
        return SUCCESS;
    }

    int32_t BeginAuthenticationExt(uint64_t, EngAuthParamExt &, std::vector<EngScheduleInfo> &,
        AcquireInfoCallback &) override
    {
        return SUCCESS;
    }

    int32_t UpdateAuthenticationResult(uint64_t, const std::vector<uint8_t> &, EngAuthResultInfo &,
        EngEnrolledState &, AcquireInfoCallback &) override
    {
        return SUCCESS;
    }

    int32_t CancelAuthentication(uint64_t) override
    {
        return SUCCESS;
    }

    int32_t GetCredential(int32_t, int32_t, std::vector<EngCredentialInfo> &) override
    {
        return SUCCESS;
    }

    int32_t DeleteCredential(int32_t, uint64_t, const std::vector<uint8_t> &,
        EngCredentialOperateResult &) override
    {
        return SUCCESS;
    }

    int32_t GetAvailableStatus(int32_t, int32_t, uint32_t, int32_t &) override
    {
        return SUCCESS;
    }

    int32_t GetUserInfo(int32_t, uint64_t &, int32_t &, std::vector<EnrolledInfo> &) override
    {
        return SUCCESS;
    }

    int32_t DeleteUser(int32_t, const std::vector<uint8_t> &, std::vector<EngCredentialInfo> &,
        std::vector<uint8_t> &) override
    {
        return SUCCESS;
    }

    int32_t EnforceDeleteUser(int32_t, std::vector<EngCredentialInfo> &) override
    {
        return SUCCESS;
    }

    int32_t GetAllExtUserInfo(std::vector<EngExtUserInfo> &) override
    {
        return SUCCESS;
    }

    int32_t GetCredentialById(uint64_t, EngCredentialInfo &) override
    {
        return SUCCESS;
    }

    int32_t ClearUnavailableCredential(const std::vector<int32_t> &, std::vector<EngCredentialInfo> &) override
    {
        return SUCCESS;
    }

    int32_t DeleteSubProfile(int32_t, int32_t, std::vector<EngCredentialInfo> &) override
    {
        return SUCCESS;
    }

    int32_t UpdateAbandonResult(int32_t, const std::vector<uint8_t> &, std::vector<EngCredentialInfo> &) override
    {
        return SUCCESS;
    }

    int32_t BeginIdentification(uint64_t, int32_t, const std::vector<uint8_t> &, uint32_t,
        EngScheduleInfo &) override
    {
        return SUCCESS;
    }

    int32_t UpdateIdentificationResult(uint64_t, const std::vector<uint8_t> &, EngIdentifyResultInfo &) override
    {
        return SUCCESS;
    }

    int32_t CancelIdentification(uint64_t) override
    {
        return SUCCESS;
    }

    int32_t BeginEnrollmentExt(const std::vector<uint8_t> &, const EngEnrollParamExt &, EngScheduleInfo &) override
    {
        return SUCCESS;
    }

    int32_t SendMessage(uint64_t, int32_t, const std::vector<uint8_t> &) override
    {
        return SUCCESS;
    }

    int32_t GetSignedExecutorInfo(const std::vector<int32_t> &, int32_t, const std::string &,
        std::vector<uint8_t> &) override
    {
        return SUCCESS;
    }

    int32_t PrepareRemoteAuth(const std::string &) override
    {
        return SUCCESS;
    }

    int32_t GetEnrolledState(int32_t, int32_t, EngEnrolledState &) override
    {
        return SUCCESS;
    }

    int32_t SetGlobalConfigParam(const EngGlobalConfigParam &) override
    {
        return SUCCESS;
    }

    int32_t SetUserConfigParam(const EngGlobalConfigParam &) override
    {
        return SUCCESS;
    }

    int32_t GetUserConfigParam(int32_t, int32_t, int32_t, EngGlobalConfigValue &) override
    {
        return SUCCESS;
    }

    int32_t VerifyAuthToken(int32_t, const std::vector<uint8_t> &, uint64_t, EngUserAuthTokenPlain &,
        EngUserAuthTokenExtraInfo &) override
    {
        return SUCCESS;
    }

    int32_t RegisterMessageCallback(const sptr<IMessageCallback> &) override
    {
        return SUCCESS;
    }

    int32_t GetValidSolution(int32_t, const std::vector<int32_t> &, uint32_t, std::vector<int32_t> &) override
    {
        return SUCCESS;
    }

    int32_t CheckReuseUnlockResult(const EngReuseUnlockParam &, EngReuseUnlockInfo &) override
    {
        return SUCCESS;
    }

    int32_t GetLocalScheduleFromMessage(const std::string &, const std::vector<uint8_t> &,
        EngScheduleInfo &) override
    {
        return SUCCESS;
    }

    int32_t GetAuthResultFromMessage(const std::string &, const std::vector<uint8_t> &,
        EngAuthResultInfo &) override
    {
        return SUCCESS;
    }

    int32_t GetLatestEnrollmentTime(int32_t, int32_t, uint64_t &) override
    {
        return SUCCESS;
    }

    bool SetStatusCallback(const StateCallback &) override
    {
        return true;
    }

    int32_t Load() override
    {
        return SUCCESS;
    }

    int32_t Unload() override
    {
        return SUCCESS;
    }

    bool IsWidgetCallerAllowedOnLockScreen(const EngCallerAuthInfo &) const override
    {
        return false;
    }
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_DUMMY_USER_AUTH_ENGINE_H
