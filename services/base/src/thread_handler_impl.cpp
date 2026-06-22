/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "thread_handler_impl.h"

#include <cstdint>
#include <functional>
#include <future>
#include <memory>

#include "nocopyable.h"

#include "iam_logger.h"
#include "iam_ptr.h"
#include "thread_handler_manager.h"
#include "xcollie_helper.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_THREAD_HANDLER_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS;
using namespace OHOS::UserIam::Common;
constexpr uint32_t TASK_BLOCK_MONITOR_TIMEOUT = 20;

ThreadHandlerImpl::ThreadHandlerImpl(std::string name, bool canSuspend) : pool_(name), canSuspend_(canSuspend)
{
    pool_.Start(1);
}

ThreadHandlerImpl::~ThreadHandlerImpl()
{
}

void ThreadHandlerImpl::PostTask(const Task &task)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (isSuspended_) {
        IAM_LOGE("is suspended");
        return;
    }
    pool_.AddTask(task);

    auto taskBlockMonitor = MakeShared<XCollieHelper>("taskBlockMonitor", TASK_BLOCK_MONITOR_TIMEOUT);
    if (taskBlockMonitor == nullptr) {
        IAM_LOGE("taskBlockMonitor is nullptr");
        return;
    }
    pool_.AddTask([taskBlockMonitor] {
        (void)taskBlockMonitor;
    });
}

void ThreadHandlerImpl::EnsureTask(const Task &task)
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

void ThreadHandlerImpl::Suspend()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!canSuspend_) {
        IAM_LOGE("can not suspend");
        return;
    }
    isSuspended_ = true;
}

std::shared_ptr<ThreadHandler> ThreadHandler::GetSingleThreadInstance()
{
    return ThreadHandlerManager::GetInstance().GetThreadHandler(SINGLETON_THREAD_NAME);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS