/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "load_mode_handler.h"

#include "iam_logger.h"

#ifdef ENABLE_DYNAMIC_LOAD
#include "load_mode_handler_dynamic.h"
#else
#include "load_mode_handler_default.h"
#endif

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
LoadModeHandler &LoadModeHandler::GetInstance()
{
#ifdef ENABLE_DYNAMIC_LOAD
    static LoadModeHandlerDynamic instance;
#else
    static LoadModeHandlerDefault instance;
#endif

    instance.Init();
    return instance;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS