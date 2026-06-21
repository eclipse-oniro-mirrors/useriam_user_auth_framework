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

#include "set_widget_param_callback_service.h"

#include <mutex>

#include "attributes.h"
#include "iam_logger.h"
#include "iam_check.h"
#include "user_auth_common_defines.h"
#include "user_auth_types.h"
#include "context.h"
#include "context_pool.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
SetWidgetParamCallbackService::SetWidgetParamCallbackService(uint64_t contextId)
    : contextId_(contextId)
{}

SetWidgetParamCallbackService::~SetWidgetParamCallbackService()
{}

int32_t SetWidgetParamCallbackService::OnSetRemoteAuthWidgetParam(const IpcWidgetParamInner& ipcWidgetParam,
    const sptr<IModalCallback>& modalCallback)
{
    IAM_LOGI("start");
    auto context = ContextPool::Instance().Select(contextId_).lock();
    if (context == nullptr) {
        IAM_LOGE("context is nullptr");
        return GENERAL_ERROR;
    }
    WidgetParamInner widgetParam = {};
    widgetParam.title = ipcWidgetParam.title;
    widgetParam.navigationButtonText = ipcWidgetParam.navigationButtonText;
    widgetParam.windowMode = static_cast<WindowModeType>(ipcWidgetParam.windowMode);
    if (widgetParam.windowMode == WindowModeType::UNKNOWN_WINDOW_MODE) {
        widgetParam.windowMode = WindowModeType::DIALOG_BOX;
    }
    widgetParam.hasContext = ipcWidgetParam.hasContext;
    context->SetRemoteAuthParam(widgetParam, modalCallback);
    return SUCCESS;
}

int32_t SetWidgetParamCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t SetWidgetParamCallbackService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
