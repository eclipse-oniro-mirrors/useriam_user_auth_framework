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

#ifndef IAM_THREAD_HANDLER_H
#define IAM_THREAD_HANDLER_H

#include <cstdint>
#include <functional>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ThreadHandler {
public:
    using Task = std::function<void(void)>;
    static constexpr uint32_t DEFAULT_TASK_TIMEOUT_SEC = 20;
    virtual ~ThreadHandler() = default;
    virtual void PostTask(const Task &task, uint32_t timeoutSec = DEFAULT_TASK_TIMEOUT_SEC) = 0;
    virtual void EnsureTask(const Task &task) = 0;
    virtual void Suspend() = 0;
    static std::shared_ptr<ThreadHandler> GetSingleThreadInstance();
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_THREAD_HANDLER_H