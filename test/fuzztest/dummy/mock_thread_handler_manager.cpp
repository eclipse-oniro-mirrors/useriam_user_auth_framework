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

#include "mock_thread_handler_manager.h"

#include <map>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "thread_handler_impl.h"
#include "thread_handler_singleton_impl.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_THREAD_HANDLER_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ThreadHandlerManager &ThreadHandlerManager::GetInstance()
{
    static ThreadHandlerManager manager;
    return manager;
}

ThreadHandlerManager::ThreadHandlerManager()
{
    IAM_LOGD("start.");
}

ThreadHandlerManager::~ThreadHandlerManager()
{
    IAM_LOGD("start.");
}

bool ThreadHandlerManager::CreateThreadHandler(const std::string &name)
{
    IAM_LOGD("start.");
    return true;
}

void ThreadHandlerManager::DestroyThreadHandler(const std::string &name)
{
    IAM_LOGD("start.");
}

void ThreadHandlerManager::DeleteThreadHandler(const std::string &name)
{
    IAM_LOGD("start.");
}

std::shared_ptr<ThreadHandler> ThreadHandlerManager::GetThreadHandler(const std::string &name)
{
    IAM_LOGD("start.");
    return nullptr;
}

void ThreadHandlerManager::PostTask(const std::string &name, const std::function<void()> &task)
{
    IAM_LOGD("start.");
}

void ThreadHandlerManager::PostTaskOnTemporaryThread(const std::string &name, const std::function<void()> &task)
{
    IAM_LOGD("start.");
}

void ThreadHandlerManager::Stop()
{
    IAM_LOGD("start.");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS