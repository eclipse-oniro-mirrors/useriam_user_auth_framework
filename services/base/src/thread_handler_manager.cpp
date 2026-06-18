/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "thread_handler_manager.h"

#include <map>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "thread_handler_impl.h"
#include "thread_handler_singleton_impl.h"

#define LOG_FILE_ID LOG_FILE_THREAD_HANDLER_MANAGER
#define LOG_TAG "USER_AUTH_SA"

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
    threadHandlerMap_.emplace(SINGLETON_THREAD_NAME,
        Common::MakeShared<ThreadHandlerSingletonImpl>());
}

ThreadHandlerManager::~ThreadHandlerManager()
{
    IAM_LOGD("start.");
    Stop();
}

bool ThreadHandlerManager::CreateThreadHandler(const std::string &name)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (threadHandlerMap_.find(name) != threadHandlerMap_.end()) {
        IAM_LOGE("thread handler %{public}s already exist", name.c_str());
        return false;
    }
    auto threadHandler = Common::MakeShared<ThreadHandlerImpl>(name, true);
    IF_FALSE_LOGE_AND_RETURN_VAL(threadHandler != nullptr, false);
    threadHandlerMap_.emplace(name, threadHandler);
    IAM_LOGI("thread handler %{public}s create success", name.c_str());
    return true;
}

void ThreadHandlerManager::DestroyThreadHandler(const std::string &name)
{
    if (name == SINGLETON_THREAD_NAME) {
        IAM_LOGE("thread handler %{public}s cannot detroy", name.c_str());
        return;
    }

    std::lock_guard<std::recursive_mutex> lock(mutex_);

    if (threadHandlerMap_.find(name) == threadHandlerMap_.end()) {
        IAM_LOGE("thread handler %{public}s not exist", name.c_str());
        return;
    }

    auto threadHandler = threadHandlerMap_[name];
    IF_FALSE_LOGE_AND_RETURN(threadHandler != nullptr);
    threadHandler->PostTask([name]() {
        auto threadHandler = ThreadHandlerManager::GetInstance().GetThreadHandler(SINGLETON_THREAD_NAME);
        IF_FALSE_LOGE_AND_RETURN(threadHandler != nullptr);
        threadHandler->PostTask([name]() {
            ThreadHandlerManager::GetInstance().DeleteThreadHandler(name);
            IAM_LOGI("thread handler %{public}s deleted", name.c_str());
        });
        IAM_LOGI("thread handler %{public}s delete task posted", name.c_str());
    });
    threadHandler->Suspend();
    IAM_LOGI("thread handler %{public}s destroy started", name.c_str());
}

void ThreadHandlerManager::DeleteThreadHandler(const std::string &name)
{
    if (name == SINGLETON_THREAD_NAME) {
        IAM_LOGE("thread handler %{public}s cannot delete", name.c_str());
        return;
    }

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (threadHandlerMap_.find(name) == threadHandlerMap_.end()) {
        IAM_LOGE("thread handler %{public}s not exist", name.c_str());
        return;
    }

    threadHandlerMap_.erase(name);
    IAM_LOGI("thread handler %{public}s is deleted", name.c_str());
}

std::shared_ptr<ThreadHandler> ThreadHandlerManager::GetThreadHandler(const std::string &name)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (threadHandlerMap_.find(name) == threadHandlerMap_.end()) {
        IAM_LOGE("thread handler %{public}s not exist", name.c_str());
        return nullptr;
    }
    return threadHandlerMap_[name];
}

void ThreadHandlerManager::PostTask(const std::string &name, const std::function<void()> &task)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (threadHandlerMap_.find(name) == threadHandlerMap_.end()) {
        IAM_LOGE("thread handler %{public}s not exist", name.c_str());
        return;
    }
    auto threadHandler = threadHandlerMap_[name];
    IF_FALSE_LOGE_AND_RETURN(threadHandler != nullptr);
    threadHandler->PostTask(task);
}

void ThreadHandlerManager::PostTaskOnTemporaryThread(const std::string &name, const std::function<void()> &task)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    static std::atomic<uint32_t> serial = 0;
    uint32_t thisSerial = serial.fetch_add(1);
    std::string thread_name = name + "_" + std::to_string(thisSerial);
    CreateThreadHandler(thread_name);
    PostTask(thread_name, task);
    DestroyThreadHandler(thread_name);
}

void ThreadHandlerManager::Stop()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    threadHandlerMap_.clear();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS