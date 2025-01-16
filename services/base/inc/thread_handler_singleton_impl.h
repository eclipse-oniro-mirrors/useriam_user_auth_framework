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

#ifndef IAM_THREAD_HANDLER_SINGLETON_IMPL_H
#define IAM_THREAD_HANDLER_SINGLETON_IMPL_H

#include <mutex>

#include "nocopyable.h"

#include "thread_handler.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ThreadHandlerSingletonImpl : public ThreadHandler, NoCopyable {
public:
    ThreadHandlerSingletonImpl() = default;
    ~ThreadHandlerSingletonImpl() override = default;
    void PostTask(const Task &task) override;
    void EnsureTask(const Task &task) override;
    void Suspend() override;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_THREAD_HANDLER_SINGLETON_IMPL_H