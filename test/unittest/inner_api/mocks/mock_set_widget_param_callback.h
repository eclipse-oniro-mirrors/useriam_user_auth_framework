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

#ifndef MOCK_SET_WIDGET_PARAM_CALLBACK_H
#define MOCK_SET_WIDGET_PARAM_CALLBACK_H

#include <gmock/gmock.h>
#include <iremote_stub.h>

#include "iset_widget_param_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockSetWidgetParamCallback final : public IRemoteStub<ISetWidgetParamCallback> {
public:
    MOCK_METHOD4(OnRemoteRequest,
        int32_t(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD2(OnSetRemoteAuthWidgetParam,
        int32_t(const IpcWidgetParamInner &ipcWidgetParamInner, const sptr<IModalCallback> &modalCallback));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MOCK_SET_WIDGET_PARAM_CALLBACK_H
