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

#ifndef MOCK_IAUTH_DRIVER_HDI_H
#define MOCK_IAUTH_DRIVER_HDI_H

#include "gmock/gmock.h"

#include "iam_executor_iauth_driver_hdi.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS::UserIam;
using namespace OHOS::UserIam::UserAuth;

class MockIAuthDriverHdi : public IAuthDriverHdi {
public:
    MOCK_METHOD1(GetExecutorList, void(std::vector<std::shared_ptr<IAuthExecutorHdi>> &executorList));
    MOCK_METHOD0(OnHdiDisconnect, void());
    MOCK_METHOD0(OnFrameworkDown, void());
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // MOCK_IAUTH_DRIVER_HDI_H