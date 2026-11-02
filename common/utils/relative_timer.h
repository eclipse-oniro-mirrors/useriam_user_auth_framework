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

#ifndef IAM_RELATIVE_TIMER_H
#define IAM_RELATIVE_TIMER_H

#include "singleton.h"
#include "timer.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class RelativeTimer final : public DelayedRefSingleton<RelativeTimer> {
    DECLARE_DELAYED_REF_SINGLETON(RelativeTimer);

public:
    using TimerCallback = std::function<void()>;
    uint32_t Register(const TimerCallback &callback, uint32_t ms, bool once = true);
    void Unregister(uint32_t timerId);

private:
    Utils::Timer timer_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_RELATIVE_TIMER_H