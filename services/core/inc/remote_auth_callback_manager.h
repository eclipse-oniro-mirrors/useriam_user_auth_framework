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

#ifndef REMOTE_AUTH_CALLBACK_MANAGER
#define REMOTE_AUTH_CALLBACK_MANAGER

#include <memory>
#include <mutex>
#include <map>

#include "iam_common_defines.h"
#include "iremote_auth_callback.h"
#include "nocopyable.h"
#include "iremote_object.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using DeathRecipient = IRemoteObject::DeathRecipient;
class RemoteAuthCallbackManager {
public:
    static RemoteAuthCallbackManager &GetInstance();
    int32_t AddRemoteAuthCallback(uint32_t tokenId,
        const sptr<IRemoteAuthCallback> &remoteAuthCallback, std::string &callerName);
    int32_t DelRemoteAuthCallback(uint32_t tokenId);
    sptr<IRemoteAuthCallback> GetRemoteAuthCallback(uint32_t tokenId);
    std::string GetRemoteAuthCallerName(uint32_t tokenId);

    int32_t AddDeathRecipient(RemoteAuthCallbackManager *manager, const sptr<IRemoteAuthCallback> &listener);
    int32_t RemoveDeathRecipient(const sptr<IRemoteAuthCallback> &listener);
    std::map<sptr<IRemoteAuthCallback>, sptr<DeathRecipient>> GetCallbackDeathRecipientMap();

protected:
    class RemoteAuthCallbackDeathRecipient : public IRemoteObject::DeathRecipient, public NoCopyable {
    public:
        RemoteAuthCallbackDeathRecipient(RemoteAuthCallbackManager *manager);
        ~RemoteAuthCallbackDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

    private:
        RemoteAuthCallbackManager *remoteAuthCallbckManager_;
    };

    std::recursive_mutex mutex_;
    std::map<sptr<IRemoteAuthCallback>, sptr<DeathRecipient>> callbackDeathRecipientMap_;
    std::map<sptr<IRemoteObject>, uint32_t> remoteObjectTokenIdMap_;

private:
    struct FinderMap {
        explicit FinderMap(sptr<IRemoteObject> remoteObject) : remoteObject_(remoteObject)
        {
        }
        bool operator()(std::map<sptr<IRemoteAuthCallback>, sptr<DeathRecipient>>::value_type &pair)
        {
            return pair.first->AsObject() == remoteObject_;
        }
        sptr<IRemoteObject> remoteObject_ {nullptr};
    };
    int32_t DelRemoteAuthCallbackOnRemoteDied(const sptr<IRemoteAuthCallback> &callback);
    RemoteAuthCallbackManager();
    ~RemoteAuthCallbackManager() = default;

    std::map<uint32_t, std::pair<sptr<IRemoteAuthCallback>, std::string>> callbacks_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // REMOTE_AUTH_CALLBACK_MANAGER