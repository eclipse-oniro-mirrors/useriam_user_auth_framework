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

#include "relative_timer.h"

#include "iam_logger.h"

#define LOG_FILE_ID LOG_FILE_RELATIVE_TIMER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
#define LOG_TAG "USER_AUTH_SA"

RelativeTimer::RelativeTimer() : timer_("iam_relative_timer")
{
    timer_.Setup();
    IAM_LOGI("relative timer setup");
}

RelativeTimer::~RelativeTimer()
{
    timer_.Shutdown();
    IAM_LOGI("relative timer shutdown");
}

uint32_t RelativeTimer::Register(const TimerCallback &callback, uint32_t ms, bool once)
{
    return timer_.Register(callback, ms, once);
}

void RelativeTimer::Unregister(uint32_t timerId)
{
    return timer_.Unregister(timerId);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
