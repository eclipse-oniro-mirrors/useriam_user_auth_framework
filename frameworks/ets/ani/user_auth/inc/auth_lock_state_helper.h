/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef AUTH_LOCK_STATE_HELPER
#define AUTH_LOCK_STATE_HELPER

#include <future>
#include <mutex>

#include "user_auth_client_callback.h"

namespace userAuth = ohos::userIAM::userAuth::userAuth;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
struct GetAuthLockStateResult {
    int32_t resultCode;
    std::vector<uint8_t> authLockState;
};

class GetAuthLockStateCallback : public UserAuth::GetPropCallback {
public:
    GetAuthLockStateCallback()
    {
        future_ = promise_.get_future().share();
    }

    virtual ~GetAuthLockStateCallback() = default;

    void OnResult(int32_t result, const UserAuth::Attributes &extraInfo) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!resultSet_) {
            GetAuthLockStateResult getAuthLockStateResult{result, extraInfo.Serialize()};
            promise_.set_value(getAuthLockStateResult);
            resultSet_ = true;
        }
    }

    std::shared_future<GetAuthLockStateResult> GetFuture()
    {
        return future_;
    }

private:
    std::mutex mutex_;
    std::promise<GetAuthLockStateResult> promise_;
    std::shared_future<GetAuthLockStateResult> future_;
    bool resultSet_ = false;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // AUTH_LOCK_STATE_HELPER