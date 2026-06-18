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

#include "js_user_auth_extension.h"

#include "js_runtime.h"
#include "js_ui_extension_base.h"

#include "iam_logger.h"

#define LOG_FILE_ID LOG_FILE_JS_USER_AUTH_EXTENSION
#define LOG_TAG "USER_AUTH_NAPI"

namespace OHOS {
namespace AbilityRuntime {
JsUserAuthExtension *JsUserAuthExtension::Create(const std::unique_ptr<Runtime> &runtime)
{
    return new JsUserAuthExtension(runtime);
}

JsUserAuthExtension::JsUserAuthExtension(const std::unique_ptr<Runtime> &runtime)
{
    IAM_LOGD("JsUserAuthExtension constructor.");
    auto uiExtensionBaseImpl = std::make_shared<JsUIExtensionBase>(runtime);
    SetUIExtensionBaseImpl(std::move(uiExtensionBaseImpl));
}

JsUserAuthExtension::~JsUserAuthExtension()
{
    IAM_LOGD("JsUserAuthExtension destructor.");
}
}
}
