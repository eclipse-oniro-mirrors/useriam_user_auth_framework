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

#ifndef USER_AUTH_MODAL_CALLBACK_H
#define USER_AUTH_MODAL_CALLBACK_H

#include <string>

#include "modal_extension_callback.h"
#include "user_auth_modal_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthModalCallback : public UserAuthModalClientCallback {
public:
    explicit UserAuthModalCallback(const std::shared_ptr<AbilityRuntime::Context> context);
    explicit UserAuthModalCallback(const sptr<OHOS::Rosen::Window> window);
    ~UserAuthModalCallback();
    void SendCommand(uint64_t contextId, const std::string &cmdData) override;
    bool IsModalInit() override;
    bool IsModalDestroy() override;

private:
    void CancelAuthentication(uint64_t contextId, int32_t cancelReason) override;
    Ace::UIContent *InitAndGetUIContent();
    bool CreateUIExtension(uint64_t contextId, const std::string &cmdData);
    void ReleaseModal();

    std::shared_ptr<AbilityRuntime::Context> context_ {nullptr};
    std::shared_ptr<ModalExtensionCallback> uiExtCallback_ {nullptr};
    sptr<OHOS::Rosen::Window> window_;
    uint64_t contextId_ {0};
    bool isInit_ {false};
    bool isInitError_ {false};
    std::recursive_mutex mutex_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_MODAL_CALLBACK_H