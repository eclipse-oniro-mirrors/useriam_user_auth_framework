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

/**
 * @file user_idm_client.h
 *
 * @brief The definition of idm client.
 * @since 3.1
 * @version 3.2
 */

#ifndef USER_IDM_CLIENT_H
#define USER_IDM_CLIENT_H

#include <memory>
#include <optional>
#include <vector>

#include "iam_common_defines.h"
#include "user_idm_client_callback.h"
#include "user_idm_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserIdmClient {
public:
    /**
     * @brief Get userIdm client's instance.
     *
     * @return UserIdmClient's instance.
     */
    static UserIdmClient &GetInstance();

    /**
     * @brief Deconstructor.
     */
    virtual ~UserIdmClient() = default;

    /**
     * @brief Open session with user identity management.
     *
     * User identity Management can be used only after the session is open,
     * and the session is valid for ten minutes.
     * @param userId System userId, generated by account subsystem.
     * @return Return the challenge.
     */
    virtual std::vector<uint8_t> OpenSession(int32_t userId) = 0;

    /**
     * @brief Open session with user identity management.
     *
     * @param userId System userId, generated by account subsystem.
     */
    virtual void CloseSession(int32_t userId) = 0;

    /**
     * @brief Add user credential information.
     *
     * @param userId System userId, generated by account subsystem.
     * @param para Include authType, pinSubType and token.
     * @param callback Callback of add credential result.
     */
    virtual void AddCredential(int32_t userId, const CredentialParameters &para,
        const std::shared_ptr<UserIdmClientCallback> &callback) = 0;

    /**
     * @brief Update user credential information.
     *
     * @param userId System userId, generated by account subsystem.
     * @param para Include authType, pinSubType and token(PIN).
     * @param callback Callback of update credential result.
     */
    virtual void UpdateCredential(int32_t userId, const CredentialParameters &para,
        const std::shared_ptr<UserIdmClientCallback> &callback) = 0;

    /**
     * @brief Cancel add user credential.
     *
     * @param userId System userId, generated by account subsystem.
     * @return Return Cancel result(0:success; other:failed).
     */
    virtual int32_t Cancel(int32_t userId) = 0;

    /**
     * @brief Delete user's credential according to credentialId.
     *
     * Only support to delete non-password credentials.
     *
     * @param userId System userId, generated by account subsystem.
     * @param credentialId User credentialId.
     * @param authToken PIN auth token.
     * @param callback Callback of delete credential result.
     */
    virtual void DeleteCredential(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
        const std::shared_ptr<UserIdmClientCallback> &callback) = 0;

    /**
     * @brief Delete user's PIN.
     *
     * When deleting user's PIN, all credentials of the user will be deleted.
     *
     * @param userId System userId, generated by account subsystem.
     * @param authToken PIN auth token.
     * @param callback Callback of delete user's credential result.
     */
    virtual void DeleteUser(int32_t userId, const std::vector<uint8_t> &authToken,
        const std::shared_ptr<UserIdmClientCallback> &callback) = 0;

    /**
     * @brief Erase user.
     *
     * This method is used for administrators to delete user and
     * delete all credentials of the user at the same time.
     *
     * @param userId System userId, generated by account subsystem.
     * @param callback Callback of erase user result.
     * @return Return erase user success or not(0:success; other:failed).
     */
    virtual int32_t EraseUser(int32_t userId, const std::shared_ptr<UserIdmClientCallback> &callback) = 0;

    /**
     * @brief get user's credential information.
     *
     * @param userId System userId, generated by account subsystem.
     * @param authType Authtype supported by executor.
     * @param callback Callback of get credentialInfo result.
     * @return Return get credentialInfo success or not(0:success; other:failed).
     */
    virtual int32_t GetCredentialInfo(int32_t userId, AuthType authType,
        const std::shared_ptr<GetCredentialInfoCallback> &callback) = 0;

    /**
     * @brief get security user information.
     *
     * @param userId System userId, generated by account subsystem.
     * @param callback Return get security userInfo result.
     * @return Return get security userInfo success or not(0:success; other:failed).
     */
    virtual int32_t GetSecUserInfo(int32_t userId, const std::shared_ptr<GetSecUserInfoCallback> &callback) = 0;

    /**
     * @brief clear redundancy credential.
     *
     * @param callback Callback of delete credentialInfo result.
     * @return Return delete userInfo success or not(0:success; other:failed).
     */
    virtual void ClearRedundancyCredential(const std::shared_ptr<UserIdmClientCallback> &callback) = 0;

    /**
     * @brief Regist cred change event listener, support repeated registration. Note that you need to listen useriam
     *        process status, and if the process is restarted abnormally, need to re-register the listener.
     *
     * @param authTypes Auth type list supported by executor, auth type include PIN, FACE, FINGERPRINT.
     * @param listener Callback of cred change success event.
     * @return Return regist result(0:success; other:failed).
     */
    virtual int32_t RegistCredChangeEventListener(const std::vector<AuthType> &authTypes,
        const std::shared_ptr<CredChangeEventListener> &listener) = 0;

    /**
     * @brief unRegist cred change event listener.
     *
     * @param listener Callback of cred change event.
     * @return Return unregist result(0:success; other:failed).
     */
    virtual int32_t UnRegistCredChangeEventListener(const std::shared_ptr<CredChangeEventListener> &listener) = 0;

    /**
     * @brief get user's credential information.
     *
     * @param userId System userId, generated by account subsystem.
     * @param authType Authtype supported by executor.
     * @param credentialInfoList credentialInfo result.
     * @return Return get credentialInfo success or not(0:success; other:failed).
     */
    virtual int32_t GetCredentialInfoSync(int32_t userId, AuthType authType,
        std::vector<CredentialInfo> &credentialInfoList) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_IDM_CLIENT_H