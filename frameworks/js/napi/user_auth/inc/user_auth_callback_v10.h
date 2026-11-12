/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef USER_AUTH_CALLBACK_V10_H
#define USER_AUTH_CALLBACK_V10_H

#include <mutex>

#include "nocopyable.h"

#include "auth_common.h"
#include "iam_common_defines.h"
#include "user_auth_napi_helper.h"
#include "user_auth_client.h"
#include "user_auth_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

class UserAuthCallbackV10 : public AuthenticationCallback,
                            public std::enable_shared_from_this<UserAuthCallbackV10>,
                            public NoCopyable {
public:
    explicit UserAuthCallbackV10(napi_env env);
    ~UserAuthCallbackV10() override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;
    void OnResult(int32_t result, const Attributes &extraInfo) override;

    napi_status DoResultCallback(const ResultInfo &resultInfo);
    napi_status DoTipInfoCallBack(int32_t tipType, uint32_t tipCode);
    napi_status DoAcquireInfoCallBack(int32_t module, int32_t acquireInfo,
        const std::vector<uint8_t> &extraInfo);
    void SetResultCallback(const std::shared_ptr<JsRefHolder> &resultCallback);
    void ClearResultCallback();
    bool HasResultCallback();
    void SetTipCallback(const std::shared_ptr<JsRefHolder> &tipCallback);
    void ClearTipCallback();
    bool HasTipCallback();
    void SetAcquireCallback(const std::shared_ptr<JsRefHolder> &acquireCallback);
    void ClearAcquireCallback();
    bool HasAcquireCallback();

private:
    std::shared_ptr<JsRefHolder> GetResultCallback();
    std::shared_ptr<JsRefHolder> GetTipCallback();
    std::shared_ptr<JsRefHolder> GetAcquireCallback();
    void SendTipInfoEvent(int32_t tipType, int32_t tipCode);
    void SendAcquireInfoEvent(int32_t module, int32_t acquireInfo, const std::vector<uint8_t> &extraInfo);
    void FillResultInfo(const Attributes &extraInfo, ResultInfo &resultInfo);

    napi_env env_ = nullptr;
    std::mutex mutex_;
    std::shared_ptr<JsRefHolder> resultCallback_ = nullptr;
    std::shared_ptr<JsRefHolder> tipCallback_ = nullptr;
    std::shared_ptr<JsRefHolder> acquireCallback_ = nullptr;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_CALLBACK_V10_H
