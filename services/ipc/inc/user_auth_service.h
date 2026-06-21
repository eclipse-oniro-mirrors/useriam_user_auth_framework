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

#ifndef USER_AUTH_SERVICE_H
#define USER_AUTH_SERVICE_H

#include "user_auth_stub.h"

#include <string>
#include <system_ability.h>
#include <system_ability_definition.h>

#include "context_callback.h"
#include "context_factory.h"
#include "context_pool.h"
#include "resource_node_pool.h"
#include "user_idm_database.h"
#include "attributes.h"
#include "user_auth_types.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthService : public SystemAbility, public UserAuthStub, public NoCopyable {
public:
    DECLARE_SYSTEM_ABILITY(UserAuthService);
    static std::shared_ptr<UserAuthService> GetInstance();

    UserAuthService();
    ~UserAuthService() override = default;
    int32_t GetAvailableStatus(int32_t apiVersion, int32_t userId, int32_t authType,
        uint32_t authTrustLevel, int32_t &funcResult) override;
    int32_t GetAvailableStatus(int32_t apiVersion, int32_t authType, uint32_t authTrustLevel,
        int32_t &funcResult) override;
    int32_t GetProperty(int32_t userId, int32_t authType, const std::vector<uint32_t> &keys,
        const sptr<IGetExecutorPropertyCallback> &getExecutorPropertyCallback) override;
    int32_t GetPropertyById(uint64_t credentialId, const std::vector<uint32_t> &keys,
        const sptr<IGetExecutorPropertyCallback> &getExecutorPropertyCallback) override;
    int32_t SetProperty(int32_t userId, int32_t authType, const std::vector<uint8_t> &attributes,
        const sptr<ISetExecutorPropertyCallback> &setExecutorPropertyCallback) override;
    int32_t AuthUser(const IpcAuthParamInner &ipcAuthParamInner, const IpcRemoteAuthParam &ipcRemoteAuthParam,
        const sptr<IIamCallback> &userAuthCallback, uint64_t &contextId) override;
    int32_t Auth(int32_t apiVersion, const IpcAuthParamInner &ipcAuthParamInner,
        const sptr<IIamCallback> &userAuthCallback, uint64_t &contextI) override;
    int32_t AuthWidget(int32_t apiVersion, const IpcAuthParamInner &ipcAuthParamInner,
        const IpcWidgetParamInner &ipcWidgetParamInner, const sptr<IIamCallback> &userAuthCallback,
        const sptr<IModalCallback> &modalCallback, uint64_t &contextId) override;
    int32_t Identify(const std::vector<uint8_t> &challenge, int32_t authType,
        const sptr<IIamCallback> &userAuthCallback, uint64_t &contextId) override;
    int32_t CancelAuthOrIdentify(uint64_t contextId, int32_t cancelReason) override;
    int32_t GetVersion(int32_t &version) override;
    int32_t Notice(int32_t noticeType, const std::string &eventData) override;
    int32_t RegisterWidgetCallback(int32_t version, const sptr<IWidgetCallback> &widgetCallback) override;
    int32_t GetEnrolledState(int32_t apiVersion, int32_t authType, IpcEnrolledState &ipcEnrolledState,
        int32_t &funcResult) override;
    int32_t RegistUserAuthSuccessEventListener(const sptr<IEventListenerCallback> &listener) override;
    int32_t UnRegistUserAuthSuccessEventListener(const sptr<IEventListenerCallback> &listener) override;
    int32_t SetGlobalConfigParam(const IpcGlobalConfigParam &ipcGlobalConfigParam) override;
    int32_t PrepareRemoteAuth(const std::string &networkId,
        const sptr<IIamCallback> &userAuthCallback) override;
    int32_t VerifyAuthToken(const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
        const sptr<IVerifyTokenCallback> &verifyTokenCallback) override;
    int32_t QueryReusableAuthResult(const IpcAuthParamInner &ipcAuthParamInner,
        std::vector<uint8_t> &token) override;
    int32_t GetAuthLockState(int32_t authType,
        const sptr<IGetExecutorPropertyCallback> &getExecutorPropertyCallback) override;

    int32_t RegisterRemoteAuthCallback(const sptr<IRemoteAuthCallback> &remoteAuthCallback) override;
    int32_t UnregisterRemoteAuthCallback() override;

    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

protected:
    void OnStart() override;
    void OnStop() override;

private:
    int32_t GetAvailableStatusImpl(int32_t apiVersion, int32_t userId, int32_t authType,
        uint32_t authTrustLevel);
    int32_t GetAvailableStatusImpl(int32_t apiVersion, int32_t authType, uint32_t authTrustLevel);
    int32_t GetEnrolledStateImpl(int32_t apiVersion, int32_t authType, IpcEnrolledState &ipcEnrolledState);

private:
    std::shared_ptr<ContextCallback> GetAuthContextCallback(int32_t apiVersion,
        const std::vector<uint8_t> &challenge, AuthType authType, AuthTrustLevel authTrustLevel,
        const sptr<IIamCallback> &callback);
    std::shared_ptr<ContextCallback> GetAuthContextCallback(int32_t apiVersion, const AuthParamInner &authParam,
        const WidgetParamInner &widgetParam, const sptr<IIamCallback> &callback);
    bool CheckAuthTrustLevel(AuthTrustLevel authTrustLevel, int32_t authType);
    bool CheckAuthTypeOnly(const std::vector<AuthType> &checkedTypes, const std::set<AuthType> &onlyContainTypes);
    bool CheckPrivatePinEnroll(const std::vector<AuthType> &authType, std::vector<AuthType> &validType);
    int32_t CheckAuthWidgetType(const std::vector<AuthType> &authType);
    int32_t CheckCallerPermissionForUserId(const AuthParamInner &authParam);
    int32_t CheckAuthPermissionAndParam(const AuthParamInner &authParam, const WidgetParamInner &widgetParam,
        bool isBackgroundApplication);
    uint64_t StartWidgetContext(const std::shared_ptr<ContextCallback> &contextCallback,
        const AuthParamInner &authParam, const WidgetParamInner &widgetParam, std::vector<AuthType> &validType,
        ContextFactory::AuthWidgetContextPara &para, const sptr<IModalCallback> &modalCallback);
    uint64_t StartAuthContext(int32_t apiVersion, Authentication::AuthenticationPara para,
        const std::shared_ptr<ContextCallback> &contextCallback, bool needSubscribeAppState);
    uint64_t AuthRemoteUser(AuthParamInner &authParam, Authentication::AuthenticationPara &para,
        RemoteAuthParam &remoteAuthParam, const std::shared_ptr<ContextCallback> &contextCallback,
        ResultCode &failReason);
    bool ProcessAuthParamForRemoteAuth(AuthParamInner &authParam, Authentication::AuthenticationPara &para,
        RemoteAuthParam &remoteAuthParam, std::string &localNetworkId);
    uint64_t StartRemoteAuthInvokerContext(AuthParamInner authParam,
        RemoteAuthInvokerContextParam &param, const std::shared_ptr<ContextCallback> &contextCallback);
    uint64_t StartLocalRemoteAuthContext(Authentication::AuthenticationPara para,
        LocalRemoteAuthContextParam &localRemoteAuthContextParam,
        const std::shared_ptr<ContextCallback> &contextCallback);
    bool Insert2ContextPool(const std::shared_ptr<Context> &context);
    bool CheckCallerIsSystemApp();
    int32_t CheckAuthPermissionAndParam(int32_t authType, const int32_t &callerType, const std::string &callerName,
        AuthTrustLevel authTrustLevel);
    bool CheckAuthPermissionAndParam(AuthType authType, AuthTrustLevel authTrustLevel,
        const std::shared_ptr<ContextCallback> &contextCallback, Attributes &extraInfo);
    int32_t CheckWindowMode(const WidgetParamInner &widgetParam);
    int32_t CheckAuthWidgetParam(const AuthParamInner &authParam, const WidgetParamInner &widgetParam);
    int32_t CheckValidSolution(ContextFactory::AuthWidgetContextPara &para, const AuthParamInner &authParam,
        const WidgetParamInner &widgetParam, std::vector<AuthType> &validType);
    int32_t GetCallerInfo(bool isUserIdSpecified, int32_t userId, ContextFactory::AuthWidgetContextPara &para,
        std::shared_ptr<ContextCallback> &contextCallback);
    int32_t CheckCallerPermissionForPrivatePin(const AuthParamInner &authParam);
    void FillGetPropertyKeys(AuthType authType, const std::vector<Attributes::AttributeKey> &keys,
        std::vector<uint32_t> &uint32Keys);
    void FillGetPropertyValue(AuthType authType, const std::vector<Attributes::AttributeKey> &keys, Attributes &values);
    bool CompleteRemoteAuthParam(RemoteAuthParam &remoteAuthParam, const std::string &localNetworkId);
    int32_t PrepareRemoteAuthInner(const std::string &networkId, const sptr<IIamCallback> &callback);
    int32_t DoPrepareRemoteAuth(const std::string &networkId);
    int32_t GetAvailableStatusInner(int32_t apiVersion, int32_t userId, AuthType authType,
        AuthTrustLevel authTrustLevel);
    bool GetAuthTokenAttr(const HdiUserAuthTokenPlain &tokenPlain, const std::vector<uint8_t> &rootSecret,
        Attributes &extraInfo);
    std::shared_ptr<ResourceNode> GetResourseNode(AuthType authType);
    void ProcessPinExpired(int32_t ret, const AuthParamInner &authParam, std::vector<AuthType> &validType,
        ContextFactory::AuthWidgetContextPara &para);
    void ProcessWidgetSessionExclusive();
    int32_t GetPropertyHelper(int32_t userId, int32_t authType,
        const std::vector<Attributes::AttributeKey> &keys,
        const sptr<IGetExecutorPropertyCallback> &getExecutorPropertyCallback);
    int32_t GetPropertyInner(AuthType authType, const std::vector<Attributes::AttributeKey> &keys,
        const sptr<IGetExecutorPropertyCallback> &callback, std::vector<uint64_t> &templateIds);
    int32_t StartAuth(int32_t apiVersion, Authentication::AuthenticationPara &para,
        std::shared_ptr<ContextCallback> &contextCallback, uint64_t &contextId);
    int32_t StartAuthUser(AuthParamInner &authParam, std::optional<RemoteAuthParam> &remoteAuthParam,
        Authentication::AuthenticationPara &para, std::shared_ptr<ContextCallback> &contextCallback,
        uint64_t &contextId);
    int32_t StartAuthWidget(AuthParamInner &authParam, WidgetParamInner &widgetParam,
        ContextFactory::AuthWidgetContextPara &para, std::shared_ptr<ContextCallback> &contextCallback,
        const sptr<IModalCallback> &modalCallback, uint64_t &contextId);
    void InitAuthParam(const IpcAuthParamInner &ipcAuthParam, AuthParamInner &authParam);
    void InitRemoteAuthParam(const IpcRemoteAuthParam &ipcRemoteAuthParam,
        std::optional<RemoteAuthParam> &remoteAuthParam);
    void InitWidgetParam(const IpcWidgetParamInner &ipcWidgetParam, WidgetParamInner &widgetParam);
    int32_t CheckSkipLockedBiometricAuth(ContextFactory::AuthWidgetContextPara &para, const AuthParamInner &authParam,
        const WidgetParamInner &widgetParam, std::vector<AuthType> &validType);
    std::vector<AuthType> GetAuthTypesFromCredentialIds(const AuthParamInner &authParam);
    void FilterFaceNotAvailable(ContextFactory::AuthWidgetContextPara &para, std::vector<AuthType> &validType);
    static std::mutex mutex_;
    static std::shared_ptr<UserAuthService> instance_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_SERVICE_H