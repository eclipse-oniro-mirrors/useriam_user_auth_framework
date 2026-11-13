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

#ifndef USER_LAUNCH_SERVICE_CLIENT_IMPL_H
#define USER_LAUNCH_SERVICE_CLIENT_IMPL_H

#include <mutex>

#include "nocopyable.h"

#include "iuser_auth.h"
#include "ipc_client_utils.h"
#include "user_launch_service_client.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserLaunchServiceImpl final : public UserLaunchServiceClient, NoCopyable {
public:
    static UserLaunchServiceImpl &Instance();

    void RegisterLaunchService(const std::vector<LaunchServiceRegisterInfo> &serviceList,
        const std::shared_ptr<LaunchServiceListCallback> &callback) override;
    void UnRegisterLaunchService(int32_t uid, const std::optional<LaunchServiceKey> &key,
        const std::shared_ptr<LaunchServiceCallback> &callback) override;
    void GetLaunchServiceInfo(int32_t uid, const std::optional<LaunchServiceKey> &key,
        const std::shared_ptr<LaunchServiceListCallback> &callback) override;
    void GetLaunchServiceList(const std::optional<int32_t> &userId,
        const std::shared_ptr<LaunchServiceListCallback> &callback) override;
    void SetLaunchServiceState(int32_t uid, const std::vector<uint8_t> &token,
        LaunchServiceState activeState, const std::shared_ptr<LaunchServiceCallback> &callback) override;
    int32_t SetDaemonAllowedlist(int32_t userId, const std::vector<std::string> &appIdentifiers,
        bool isAdd) override;
    int32_t SetDaemonForbiddenlist(int32_t userId, const std::vector<std::string> &appIdentifiers,
        bool isAdd) override;

private:
    friend class UserLaunchServiceClient;
    UserLaunchServiceImpl() = default;
    ~UserLaunchServiceImpl() override = default;

    class UserLaunchServiceDeathRecipient : public IRemoteObject::DeathRecipient, public NoCopyable {
    public:
        UserLaunchServiceDeathRecipient() = default;
        ~UserLaunchServiceDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };
    sptr<IUserAuth> GetProxy();
    void ResetProxy(const wptr<IRemoteObject> &remote);

    sptr<IUserAuth> proxy_ {nullptr};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};
    std::mutex mutex_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_LAUNCH_SERVICE_CLIENT_IMPL_H
