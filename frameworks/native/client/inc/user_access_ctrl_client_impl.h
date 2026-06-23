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

#ifndef USER_ACCESS_CTRL_CLIENT_IMPL_H
#define USER_ACCESS_CTRL_CLIENT_IMPL_H

#include <mutex>

#include "nocopyable.h"

#include "user_access_ctrl_client.h"
#include "iuser_auth.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAccessCtrlClientImpl final : public UserAccessCtrlClient, NoCopyable {
public:
    static UserAccessCtrlClientImpl &Instance();
    void VerifyAuthToken(const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
        const std::shared_ptr<VerifyTokenCallback> &callback) override;
private:
    friend class UserAccessCtrlClient;
    UserAccessCtrlClientImpl() = default;
    ~UserAccessCtrlClientImpl() override = default;

    class UserAccessCtrlImplDeathRecipient : public IRemoteObject::DeathRecipient, public NoCopyable {
    public:
        UserAccessCtrlImplDeathRecipient() = default;
        ~UserAccessCtrlImplDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };
    void ResetProxy(const wptr<IRemoteObject> &remote);
    sptr<IUserAuth> GetProxy();
    sptr<IUserAuth> proxy_ {nullptr};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};
    std::mutex mutex_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_ACCESS_CTRL_CLIENT_IMPL_H