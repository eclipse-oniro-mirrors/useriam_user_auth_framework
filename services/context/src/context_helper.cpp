/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "context_helper.h"

#include "context_pool.h"
#include "iam_logger.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_CONTEXT_HELPER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ContextHelper::Cleaner::Cleaner(const std::shared_ptr<Context> &context)
    : contextId_(context ? context->GetContextId() : 0)
{
}

void ContextHelper::Cleaner::operator()()
{
    IAM_LOGD("start");
    if (contextId_ == 0) {
        IAM_LOGD("invalid context Id");
    }
    auto result = ContextPool::Instance().Delete(contextId_);
    IAM_LOGI("context ****%{public}hx deleted %{public}s", static_cast<uint16_t>(contextId_), result ? "succ" : "fail");
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
