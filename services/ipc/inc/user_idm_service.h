/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef USER_IDM_SERVICE_H
#define USER_IDM_SERVICE_H

#include "user_idm_stub.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "system_ability.h"
#include "system_ability_definition.h"

#include "context.h"
#include "context_factory.h"
#include "credential_info_interface.h"
#include "user_idm_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserIdmService : public SystemAbility, public UserIdmStub, public NoCopyable {
public:
    DECLARE_SYSTEM_ABILITY(UserIdmService);
    explicit UserIdmService(int32_t systemAbilityId, bool runOnCreate = false);
    ~UserIdmService() override = default;
    int Dump(int fd, const std::vector<std::u16string> &args) override;
    int32_t OpenSession(int32_t userId, std::vector<uint8_t> &challenge) override;
    int32_t CloseSession(int32_t userId) override;
    int32_t GetCredentialInfo(int32_t userId, int32_t authType,
        const sptr<IIdmGetCredInfoCallback> &idmGetCredInfoCallback, int32_t &funcResult) override;
    int32_t GetSecInfo(int32_t userId,
        const sptr<IIdmGetSecureUserInfoCallback> &idmGetSecureUserInfoCallback) override;
    int32_t AddCredential(int32_t userId, const IpcCredentialPara &ipcCredentialPara,
        const sptr<IIamCallback> &IdmCallback, bool isUpdate) override;
    int32_t UpdateCredential(int32_t userId, const IpcCredentialPara &ipcCredentialPara,
        const sptr<IIamCallback> &IdmCallback) override;
    int32_t Cancel(int32_t userId) override;
    int32_t EnforceDelUser(int32_t userId, const sptr<IIamCallback> &IdmCallback) override;
    int32_t DelUser(int32_t userId, const std::vector<uint8_t> &authToken,
        const sptr<IIamCallback> &IdmCallback) override;
    int32_t DelCredential(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
        const sptr<IIamCallback> &IdmCallback) override;
    int32_t ClearRedundancyCredential(const sptr<IIamCallback> &IdmCallback) override;
    int32_t DeleteSubProfile(int32_t subProfileId, const sptr<IIamCallback> &IdmCallback) override;
    int32_t RegistCredChangeEventListener(const sptr<IEventListenerCallback> &listener) override;
    int32_t UnRegistCredChangeEventListener(const sptr<IEventListenerCallback> &listener) override;
    int32_t GetCredentialInfoSync(int32_t userId, int32_t authType,
        std::vector<IpcCredentialInfo> &ipcCredentialInfoList) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

protected:
    void OnStart() override;
    void OnStop() override;

private:
    int32_t GetCredentialInfoImpl(int32_t userId, int32_t authType,
        const sptr<IIdmGetCredInfoCallback> &idmGetCredInfoCallback);

private:
    void CancelCurrentEnrollIfExist();
    int32_t GetSecInfoInner(int32_t userId, SecUserInfo &secUserInfo);
    int32_t GetCredentialInfoInner(int32_t userId, AuthType authType, std::vector<CredentialInfo> &credInfoList);
    int32_t EnforceDelUserInner(int32_t userId, std::shared_ptr<ContextCallback> callbackForTrace,
        std::string changeReasonTrace, CredChangeEventInfo &changeInfo);
    void PostProcessForDelete(int32_t userId, std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos,
        std::string changeReasonTrace, CredChangeEventType eventType, CredChangeEventInfo &changeInfo);
    int32_t ClearRedundancyCredentialInner(const std::string &callerName, int32_t callerType);
    void SetAuthTypeTrace(const std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos,
        const std::shared_ptr<ContextCallback> &contextCallback);
    int32_t StartEnroll(Enrollment::EnrollmentPara &para,
        const std::shared_ptr<ContextCallback> &contextCallback, Attributes &extraInfo, bool needSubscribeAppState);
    int32_t StartDelete(Deletion::DeleteParam &para, const std::shared_ptr<ContextCallback> &contextCallback,
        Attributes &extraInfo);
    void ClearUnavailableCredential(int32_t userId);
    bool GetNeedSubscribeAppState(std::string jsonText, const char *key);
    int32_t ConvertGetCredentialResult(int32_t resultCode, bool isNotEnrollReturnSuccess);
    std::string GetSessionInfoMasked(std::vector<uint8_t> &challenge);
    std::mutex mutex_;
    std::optional<uint32_t> sessionTokenId_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_IDM_SERVICE_H