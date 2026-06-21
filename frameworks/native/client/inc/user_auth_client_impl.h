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

#ifndef USER_AUTH_CLIENT_IMPL_H
#define USER_AUTH_CLIENT_IMPL_H

#include <mutex>
#include <optional>

#include "nocopyable.h"

#include "event_listener_callback_service.h"
#include "iuser_auth.h"
#include "iuser_auth_widget_callback.h"
#include "user_auth_client.h"
#include "user_auth_types.h"
#include "user_auth_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthClientImpl final : public UserAuthClient, NoCopyable {
public:
    static UserAuthClientImpl& Instance();
    int32_t GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel);
    int32_t GetNorthAvailableStatus(int32_t apiVersion, AuthType authType, AuthTrustLevel authTrustLevel);
    int32_t GetAvailableStatus(int32_t userId, AuthType authType, AuthTrustLevel authTrustLevel) override;
    void GetProperty(int32_t userId, const GetPropertyRequest &request,
        const std::shared_ptr<GetPropCallback> &callback) override;
    void GetPropertyById(uint64_t credentialId, const std::vector<Attributes::AttributeKey> &keys,
        const std::shared_ptr<GetPropCallback> &callback) override;
    void SetProperty(int32_t userId, const SetPropertyRequest &request,
        const std::shared_ptr<SetPropCallback> &callback) override;
    uint64_t BeginAuthentication(const AuthParam &authParam,
        const std::shared_ptr<AuthenticationCallback> &callback) override;
    uint64_t BeginNorthAuthentication(int32_t apiVersion, const std::vector<uint8_t> &challenge, AuthType authType,
        AuthTrustLevel atl, const std::shared_ptr<AuthenticationCallback> &callback);
    int32_t CancelAuthentication(uint64_t contextId) override;
    uint64_t BeginIdentification(const std::vector<uint8_t> &challenge, AuthType authType,
        const std::shared_ptr<IdentificationCallback> &callback) override;
    int32_t CancelIdentification(uint64_t contextId) override;
    int32_t GetVersion(int32_t &version);
    uint64_t BeginWidgetAuth(const WidgetAuthParam &authParam, const WidgetParam &widgetParam,
        const std::shared_ptr<AuthenticationCallback> &callback) override;
    uint64_t BeginWidgetAuth(int32_t apiVersion, const WidgetAuthParam &authParam, const WidgetParam &widgetParam,
        const std::shared_ptr<AuthenticationCallback> &callback);
    int32_t SetWidgetCallback(int32_t version, const std::shared_ptr<IUserAuthWidgetCallback> &callback);
    int32_t Notice(NoticeType noticeType, const std::string &eventData);
    int32_t GetEnrolledState(int32_t apiVersion, AuthType authType, EnrolledState &enrolledState);
    void GetAuthLockState(AuthType authType, const std::shared_ptr<GetPropCallback> &callback);
    int32_t RegistUserAuthSuccessEventListener(const std::vector<AuthType> &authTypes,
        const std::shared_ptr<AuthSuccessEventListener> &listener) override;
    int32_t UnRegistUserAuthSuccessEventListener(
        const std::shared_ptr<AuthSuccessEventListener> &listener) override;
    int32_t SetGlobalConfigParam(const GlobalConfigParam &param) override;
    int32_t PrepareRemoteAuth(const std::string &networkId,
        const std::shared_ptr<PrepareRemoteAuthCallback> &callback) override;
    int32_t QueryReusableAuthResult(const WidgetAuthParam &authParam, std::vector<uint8_t> &token) override;

    int32_t RegisterRemoteAuthCallback(const std::shared_ptr<RemoteAuthClientCallback> &remoteAuthCallback) override;
    int32_t UnregisterRemoteAuthCallback() override;

    void CleanUpResource();

private:
    ResultCode SetPropertyInner(int32_t userId, const SetPropertyRequest &request,
        const std::shared_ptr<SetPropCallback> &callback);
    uint64_t BeginAuthenticationInner(const AuthParam &authParam,
        const std::shared_ptr<AuthenticationCallback> &callback);
    uint64_t BeginWidgetAuthInner(int32_t apiVersion, const AuthParamInner &authParam,
        const WidgetParamInner &widgetParam, const std::shared_ptr<AuthenticationCallback> &callback);
    void InitIpcRemoteAuthParam(const std::optional<RemoteAuthParam> &remoteAuthParam,
        IpcRemoteAuthParam &ipcRemoteAuthParam);
    void InitIpcGlobalConfigParam(const GlobalConfigParam &globalConfigParam,
        IpcGlobalConfigParam &ipcGlobalConfigParam);
    void InitIpcAuthParam(const AuthParamInner &authParam, IpcAuthParamInner &ipcAuthParam);
    void InitIpcWidgetParam(const WidgetParamInner &widgetParam, IpcWidgetParamInner &ipcWidgetParam);

    friend class UserAuthClient;
    UserAuthClientImpl() = default;
    ~UserAuthClientImpl() override;
    class UserAuthImplDeathRecipient : public IRemoteObject::DeathRecipient, public NoCopyable {
    public:
        UserAuthImplDeathRecipient() = default;
        ~UserAuthImplDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };
    void ResetProxy(const wptr<IRemoteObject> &remote);
    sptr<IUserAuth> GetProxy();
    sptr<IUserAuth> proxy_ {nullptr};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};
    constexpr static int32_t MINIMUM_VERSION {0};
    std::mutex mutex_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_CLIENT_IMPL_H