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

#ifndef SET_DEVICE_SELECT_RESULT_CALLBACK_H
#define SET_DEVICE_SELECT_RESULT_CALLBACK_H

#include <memory>
#include <mutex>
#include "refbase.h"
#include "user_auth_client_defines.h"
#include "iset_widget_param_callback.h"
#include "user_auth_modal_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class SetWidgetParamClientCallback {
public:
    explicit SetWidgetParamClientCallback(const sptr<ISetWidgetParamCallback> &callback);
    ~SetWidgetParamClientCallback() = default;

    int32_t OnSetRemoteAuthWidgetParam(WidgetParamNapi &widgetParam,
        const std::shared_ptr<UserAuthModalClientCallback> &modalCallback);

private:
    std::recursive_mutex mutex_;
    sptr<ISetWidgetParamCallback> callback_ { nullptr };
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // SET_DEVICE_SELECT_RESULT_CALLBACK_H
