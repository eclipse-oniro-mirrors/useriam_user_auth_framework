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

#ifndef USER_IDM_H
#define USER_IDM_H

#include <iremote_object.h>
#include <singleton.h>
#include "iuser_idm.h"
#include "user_idm_defines.h"
#include "user_idm_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

class UserIdm : public DelayedRefSingleton<UserAuth::UserIdm> {
public:
    uint64_t OpenSession(const int32_t userId);
    void CloseSession(const int32_t userId);

    void AddCredential(const int32_t userId, const AddCredInfo& credInfo, const std::shared_ptr<IdmCallback>& callback);
    void UpdateCredential(const int32_t userId, const AddCredInfo& credInfo,
        const std::shared_ptr<IdmCallback>& callback);
    int32_t Cancel(const int32_t userId);
    void DelUser(const int32_t userId, const std::vector<uint8_t> authToken,
        const std::shared_ptr<IdmCallback>& callback);
    void DelCredential(const int32_t userId, const uint64_t credentialId, const std::vector<uint8_t> authToken,
        const std::shared_ptr<IdmCallback>& callback);

    int32_t GetAuthInfo(const int32_t userId, AuthType authType, const std::shared_ptr<GetInfoCallback>& callback);
    int32_t GetSecInfo(const int32_t userId, const std::shared_ptr<GetSecInfoCallback>& callback);
    int32_t EnforceDelUser(const int32_t userId, const std::shared_ptr<IdmCallback>& callback);

private:
    class IdmDeathRecipient : public IRemoteObject::DeathRecipient, public NoCopyable {
    public:
        IdmDeathRecipient() = default;
        ~IdmDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;
    };

    void ResetIdmProxy(const wptr<IRemoteObject>& remote);
    sptr<IUserIDM> GetIdmProxy();

    std::mutex mutex_;
    sptr<IUserIDM> proxy_ {nullptr};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};
};
}  // namespace UserAuth
}  // namespace UserIAM
}  // namespace OHOS
namespace OHOS {
namespace UserIAM {
namespace UserAuth {
using UserIdm = OHOS::UserIam::UserAuth::UserIdm;
}
}
}
#endif // USER_IDM_H