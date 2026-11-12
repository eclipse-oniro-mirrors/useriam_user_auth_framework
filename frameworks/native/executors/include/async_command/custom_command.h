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

#ifndef CUSTOM_COMMAND_H
#define CUSTOM_COMMAND_H

#include <future>

#include "async_command_base.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class CustomCommand : public AsyncCommandBase {
public:
    CustomCommand(std::weak_ptr<Executor> executor, const Attributes &attributes);
    ~CustomCommand() override = default;
    ResultCode GetResult();
    const std::vector<uint8_t> &GetExtraInfo() const;

protected:
    ResultCode SendRequest() override;
    void OnAcquireInfoInner(int32_t acquire, const std::vector<uint8_t> &extraInfo) override;
    void OnResultInner(ResultCode result, const std::vector<uint8_t> &extraInfo) override;
    void OnMessageInner(int destRole, const std::vector<uint8_t> &msg) override;

private:
    void SetResult(ResultCode resultCode);
    std::shared_ptr<Attributes> attributes_ {nullptr};
    ResultCode result_ = ResultCode::GENERAL_ERROR;
    std::vector<uint8_t> extraInfo_;
    std::promise<void> promise_;
    std::future<void> future_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // CUSTOM_COMMAND_H