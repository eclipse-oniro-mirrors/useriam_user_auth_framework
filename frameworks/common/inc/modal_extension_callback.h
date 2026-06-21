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

#ifndef MODAL_EXTENSION_CALLBACK_H
#define MODAL_EXTENSION_CALLBACK_H

#include <string>

#include "window.h"
#include "ui_content.h"
#include "ui_extension_context.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ModalExtensionCallback {
public:
    ModalExtensionCallback();
    ~ModalExtensionCallback();
    void OnRelease(int32_t code);
    void OnResult(int32_t code, const OHOS::AAFwk::Want& result);
    void OnReceive(const OHOS::AAFwk::WantParams& request);
    void OnError(int32_t code, const std::string& name, const std::string &message);
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy> &uiProxy);
    void OnDestroy();
    void SetSessionId(int32_t sessionId);
    void SetContextId(uint64_t contextId);
    void SetAbilityContext(std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext);
    void SetHolderContext(std::shared_ptr<OHOS::AbilityRuntime::UIHolderExtensionContext> uiHolderContext);
    void SetWindow(sptr<OHOS::Rosen::Window> window);
    void ReleaseOrErrorHandle(int32_t code);
    bool IsModalDestroy();

private:
    void CancelAuthentication();

    int32_t sessionId_ = 0;
    uint64_t contextId_ = 0;
    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext_;
    std::shared_ptr<OHOS::AbilityRuntime::UIHolderExtensionContext> uiHolderContext_;
    sptr<OHOS::Rosen::Window> window_;
    bool isDestroy_ {false};
    std::recursive_mutex mutex_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MODAL_EXTENSION_CALLBACK_H