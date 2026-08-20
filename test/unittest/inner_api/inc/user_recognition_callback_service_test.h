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
#ifndef USER_RECOGNITION_CALLBACK_SERVICE_TEST
#define USER_RECOGNITION_CALLBACK_SERVICE_TEST

#include <gtest/gtest.h>
#include "mock_ipc_client_utils.h"
#include "mock_remote_object.h"
#include "mock_user_auth_client_callback.h"
#include "mock_user_auth_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserRecognitionCallbackServiceTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // USER_RECOGNITION_CALLBACK_SERVICE_TEST
