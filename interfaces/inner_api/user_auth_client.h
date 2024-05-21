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
 * @file user_auth_client.h
 *
 * @brief The definition of user auth client.
 * @since 3.1
 * @version 3.2
 */

#ifndef USER_AUTH_CLIENT_H
#define USER_AUTH_CLIENT_H

#include <memory>
#include <vector>

#include "user_auth_client_callback.h"
#include "user_auth_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthClient {
public:
    /**
     * @brief Get userAuth client's instance.
     *
     * @return UserAuthClient's instance.
     */
    static UserAuthClient &GetInstance();

    /**
     * @brief Deconstructor.
     */
    virtual ~UserAuthClient() = default;

    /**
     * @brief Get executor property.
     *
     * @param userId System userId, generated by account subsystem.
     * @param request AuthType and AttributeKey to get property.
     * @param callback Callback of get property result.
     */
    virtual void GetProperty(int32_t userId, const GetPropertyRequest &request,
        const std::shared_ptr<GetPropCallback> &callback) = 0;

    /**
     * @brief Set executor property.
     *
     * @param userId System userId, generated by account subsystem.
     * @param request AuthType, propertyMode and attributes to set property.
     * @param callback Callback of set property result.
     */
    virtual void SetProperty(int32_t userId, const SetPropertyRequest &request,
        const std::shared_ptr<SetPropCallback> &callback) = 0;

    /**
     * @brief Begin user authentication according to ATL and authType.
     *
     * @param authParam, authentication paramater.
     * @param callback Callback of user authentication result.
     * @return Return context ID of authentication.
     */
    virtual uint64_t BeginAuthentication(const AuthParam &authParam,
        const std::shared_ptr<AuthenticationCallback> &callback) = 0;

    /**
     * @brief Cancel user authentication.
     *
     * @param contextId Indicates the authenticate context index.
     * @return Return cancelAuthentication result(0:success; other:failed).
     */
    virtual int32_t CancelAuthentication(uint64_t contextId) = 0;

    /**
     * @brief Begin user identification according to authType.
     *
     * @param challenge auth challenge which can prevent replay attacks.
     * @param authType Auth type supported by executor.
     * @param callback Callback of user identification result.
     * @return Return context ID of authentication.
     */
    virtual uint64_t BeginIdentification(const std::vector<uint8_t> &challenge, AuthType authType,
        const std::shared_ptr<IdentificationCallback> &callback) = 0;

    /**
     * @brief Cancel user identification.
     *
     * @param contextId Indicates the identification context index.
     * @return Return CancelIdentification result(0:success; other:failed).
     */
    virtual int32_t CancelIdentification(uint64_t contextId) = 0;

    /**
     * @brief Regist authentication success event listener, support repeated registration.
     *
     * @param authType Auth type list supported by executor, auth type include PIN, FACE, FINGERPRINT.
     * @param listener Callback of authentication success event.
     * @return Return regist result(0:success; other:failed).
     */
    virtual int32_t RegistUserAuthSuccessEventListener(const std::vector<AuthType> &authType,
        const sptr<AuthEventListenerInterface> &listener) = 0;

    /**
     * @brief unRegist authentication success event listener.
     *
     * @param listener Callback of authentication success event.
     * @return Return unregist result(0:success; other:failed).
     */
    virtual int32_t UnRegistUserAuthSuccessEventListener(
        const sptr<AuthEventListenerInterface> &listener) = 0;

    /**
     * @brief Set global config param.
     *
     * @param param The value of global config parameter.
     * @return Return set result(0:success; other:failed).
     */
    virtual int32_t SetGlobalConfigParam(const GlobalConfigParam &param) = 0;

    /**
     * @brief Prepare remote authentication.
     * @param networkId Network id of remote device.
     * @param callback Callback of prepare remote authentication result.
     *
     * @return Return prepare remote authentication result(0:success; other:failed).
     */
    virtual int32_t PrepareRemoteAuth(const std::string &networkId,
        const std::shared_ptr<PrepareRemoteAuthCallback> &callback) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_CLIENT_H