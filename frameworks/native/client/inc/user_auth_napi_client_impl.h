/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef USER_AUTH_NAPI_CLIENT_IMPL_H
#define USER_AUTH_NAPI_CLIENT_IMPL_H

#include <mutex>

#include "nocopyable.h"

#include "user_auth_client_callback.h"
#include "user_auth_client_defines.h"
#include "iuser_auth.h"
#include "user_auth_modal_client_callback.h"
#include "user_auth_types.h"
#include "user_auth_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthNapiClientImpl final : public NoCopyable {
public:
    static UserAuthNapiClientImpl& Instance();
    uint64_t BeginWidgetAuth(int32_t apiVersion, const AuthParamInner &authParam, const WidgetParamNapi &widgetParam,
        const std::shared_ptr<AuthenticationCallback> &callback,
        const std::shared_ptr<UserAuthModalClientCallback> &modalCallback);
    int32_t CancelAuthentication(uint64_t contextId, int32_t cancelReason);

private:
    uint64_t BeginWidgetAuthInner(int32_t apiVersion, const AuthParamInner &authParam,
        const WidgetParamInner &widgetParam, const std::shared_ptr<AuthenticationCallback> &callback,
        const std::shared_ptr<UserAuthModalClientCallback> &modalCallback);
    void InitIpcAuthParam(const AuthParamInner &authParam, IpcAuthParamInner &ipcWidgetParamInner);
    void InitIpcWidgetParam(const WidgetParamInner &widgetParam, IpcWidgetParamInner &ipcWidgetParamInner);

    UserAuthNapiClientImpl() = default;
    ~UserAuthNapiClientImpl() override = default;
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
#endif // USER_AUTH_NAPI_CLIENT_IMPL_H