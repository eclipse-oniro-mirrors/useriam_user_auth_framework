/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "thread_handler_singleton_impl.h"

#include <cstdint>
#include <functional>
#include <future>
#include <memory>

#include "nocopyable.h"

#include "iam_logger.h"
#include "iam_ptr.h"
#include "relative_timer.h"
#include "thread_handler_manager.h"
#include "xcollie_helper.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_THREAD_HANDLER_SINGLETON_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS;
using namespace OHOS::UserIam::Common;
constexpr uint32_t TASK_BLOCK_MONITOR_TIMEOUT = 20;

void ThreadHandlerSingletonImpl::PostTask(const Task &task)
{
    RelativeTimer::GetInstance().Register(task, 0);

    auto taskBlockMonitor = MakeShared<XCollieHelper>("taskBlockMonitor", TASK_BLOCK_MONITOR_TIMEOUT);
    if (taskBlockMonitor == nullptr) {
        IAM_LOGE("taskBlockMonitor is nullptr");
        return;
    }

    RelativeTimer::GetInstance().Register(
        [taskBlockMonitor] {
            (void)taskBlockMonitor;
        },
        0);
}

void ThreadHandlerSingletonImpl::EnsureTask(const Task &task)
{
    std::promise<void> ensure;
    auto callback = [&ensure]() {
        ensure.set_value();
        return;
    };
    PostTask(task);
    PostTask(callback);
    ensure.get_future().get();
}

void ThreadHandlerSingletonImpl::Suspend()
{
    IAM_LOGE("can not suspend");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS