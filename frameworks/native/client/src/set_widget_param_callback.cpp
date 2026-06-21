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

#include "set_widget_param_callback.h"

#include "iam_logger.h"
#include "iam_para2str.h"
#include "modal_callback_service.h"

#define LOG_TAG "USER_AUTH_SDK"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
SetWidgetParamClientCallback::SetWidgetParamClientCallback(const sptr<ISetWidgetParamCallback> &callback)
    : callback_(callback)
{
}

int32_t SetWidgetParamClientCallback::OnSetRemoteAuthWidgetParam(WidgetParamNapi &widgetParam,
    const std::shared_ptr<UserAuthModalClientCallback> &modalCallback)
{
    IAM_LOGI("start");
    if (!modalCallback) {
        IAM_LOGE("modal callback is nullptr");
        return GENERAL_ERROR;
    }

    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }

    IpcWidgetParamInner ipcWidgetParamInner = {};
    ipcWidgetParamInner.title = widgetParam.title;
    ipcWidgetParamInner.navigationButtonText = widgetParam.navigationButtonText;
    ipcWidgetParamInner.windowMode = static_cast<int32_t>(widgetParam.windowMode);
    ipcWidgetParamInner.hasContext = widgetParam.hasContext;

    sptr<IModalCallback> wrapperModal(new (std::nothrow) ModalCallbackService(modalCallback));
    if (wrapperModal == nullptr) {
        IAM_LOGE("failed to create wrapper for modal");
        return GENERAL_ERROR;
    }

    callback_->OnSetRemoteAuthWidgetParam(ipcWidgetParamInner, wrapperModal);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS