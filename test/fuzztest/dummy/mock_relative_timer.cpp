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

#include "mock_relative_timer.h"

#include "iam_logger.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_RELATIVE_TIMER

RelativeTimer::RelativeTimer()
{
    IAM_LOGI("start.");
}

RelativeTimer::~RelativeTimer()
{
    IAM_LOGI("start.");
}

uint32_t RelativeTimer::Register(const TimerCallback &callback, uint32_t ms, bool once)
{
    IAM_LOGI("start.");
    (void)callback;
    (void)ms;
    (void)once;
    return 0;
}

void RelativeTimer::Unregister(uint32_t timerId)
{
    IAM_LOGI("start.");
    (void)timerId;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
