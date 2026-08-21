/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef USER_IDM_CLIENT_IMPL_H
#define USER_IDM_CLIENT_IMPL_H

#include <mutex>

#include "nocopyable.h"

#include "event_listener_callback_service.h"
#include "iuser_idm.h"
#include "user_idm_client.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserIdmClientImpl final : public UserIdmClient, public NoCopyable {
public:
    std::vector<uint8_t> OpenSession(int32_t userId) override;
    void CloseSession(int32_t userId) override;
    void AddCredential(int32_t userId, const CredentialParameters &para,
        const std::shared_ptr<UserIdmClientCallback> &callback) override;
    void UpdateCredential(int32_t userId, const CredentialParameters &para,
        const std::shared_ptr<UserIdmClientCallback> &callback) override;
    int32_t Cancel(int32_t userId) override;
    void DeleteCredential(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
        const std::shared_ptr<UserIdmClientCallback> &callback) override;
    void DeleteUser(int32_t userId, const std::vector<uint8_t> &authToken,
        const std::shared_ptr<UserIdmClientCallback> &callback) override;
    int32_t EraseUser(int32_t userId, const std::shared_ptr<UserIdmClientCallback> &callback) override;
    int32_t GetCredentialInfo(int32_t userId, AuthType authType,
        const std::shared_ptr<GetCredentialInfoCallback> &callback) override;
    int32_t GetSecUserInfo(int32_t userId, const std::shared_ptr<GetSecUserInfoCallback> &callback) override;
    void ClearRedundancyCredential(const std::shared_ptr<UserIdmClientCallback> &callback) override;
    void DeleteSubProfile(int32_t subProfileId,
        const std::shared_ptr<UserIdmClientCallback> &callback) override;
    int32_t RegistCredChangeEventListener(const std::vector<AuthType> &authTypes,
        const std::shared_ptr<CredChangeEventListener> &listener) override;
    int32_t UnRegistCredChangeEventListener(const std::shared_ptr<CredChangeEventListener> &listener) override;
    int32_t GetCredentialInfoSync(int32_t userId, AuthType authType,
        std::vector<CredentialInfo> &credentialInfoList) override;

private:
    friend class UserIdmClient;
    UserIdmClientImpl() = default;
    ~UserIdmClientImpl() override = default;
    static UserIdmClientImpl &Instance();
    class UserIdmImplDeathRecipient : public IRemoteObject::DeathRecipient, public NoCopyable {
    public:
        UserIdmImplDeathRecipient() = default;
        ~UserIdmImplDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };
    void ResetProxy(const wptr<IRemoteObject> &remote);
    sptr<IUserIdm> GetProxy();
    sptr<IUserIdm> proxy_ {nullptr};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};
    std::mutex mutex_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_IDM_CLIENT_IMPL_H