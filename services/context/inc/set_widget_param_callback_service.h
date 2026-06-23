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

#ifndef SET_WIDGET_PARAM_CALLBACK_SERVICE_H
#define SET_WIDGET_PARAM_CALLBACK_SERVICE_H

#include "set_widget_param_callback_stub.h"

#include <memory>
#include <iremote_stub.h>
#include "iset_widget_param_callback.h"
#include "user_auth_client_callback.h"
#include "context.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class SetWidgetParamCallbackService : public SetWidgetParamCallbackStub {
public:
    explicit SetWidgetParamCallbackService(uint64_t contextId);
    ~SetWidgetParamCallbackService() override;

    int32_t OnSetRemoteAuthWidgetParam(
        const IpcWidgetParamInner &ipcWidgetParamInner, const sptr<IModalCallback> &modalCallback) override;

    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

private:
    uint64_t contextId_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // SET_WIDGET_PARAM_CALLBACK_SERVICE_H