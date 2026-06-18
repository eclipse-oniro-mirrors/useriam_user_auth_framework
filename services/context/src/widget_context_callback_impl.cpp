/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "widget_context_callback_impl.h"

#include <sstream>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_mem.h"
#include "iam_ptr.h"
#include "widget_context.h"

#define LOG_FILE_ID LOG_FILE_WIDGET_CONTEXT_CALLBACK_IMPL
#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
WidgetContextCallbackImpl::WidgetContextCallbackImpl(std::weak_ptr<WidgetContext> widgetContext, int32_t authType)
    : authType_(authType), widgetContext_(widgetContext),
    iamHitraceHelper_(Common::MakeShared<UserIam::UserAuth::IamHitraceHelper>("WidgetContext"))
{
}

int32_t WidgetContextCallbackImpl::OnResult(int32_t resultCode, const std::vector<uint8_t> &extraInfo)
{
    std::lock_guard lock(mutex_);
    auto widgetContext = widgetContext_.lock();
    if (widgetContext != nullptr) {
        Attributes attributes(extraInfo);
        widgetContext->AuthResult(resultCode, authType_, attributes);
        return SUCCESS;
    }

    return GENERAL_ERROR;
}

int32_t WidgetContextCallbackImpl::OnAcquireInfo(int32_t module, int32_t acquireInfo,
    const std::vector<uint8_t> &extraInfo)
{
    std::lock_guard lock(mutex_);
    auto widgetContext = widgetContext_.lock();
    if (widgetContext != nullptr) {
        Attributes attributes(extraInfo);
        widgetContext->AuthTipInfo(acquireInfo, authType_, attributes);
        return SUCCESS;
    }
    return GENERAL_ERROR;
}

sptr<IRemoteObject> WidgetContextCallbackImpl::AsObject()
{
    sptr<IRemoteObject> tmp(nullptr);
    return tmp;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
