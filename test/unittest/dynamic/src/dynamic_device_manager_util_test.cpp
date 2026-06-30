/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "dynamic_device_manager_util_test.h"
#include "device_manager_util.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void DynamicDeviceManagerUtilTest::SetUpTestCase()
{
}

void DynamicDeviceManagerUtilTest::TearDownTestCase()
{
}

void DynamicDeviceManagerUtilTest::SetUp()
{
}

void DynamicDeviceManagerUtilTest::TearDown()
{
}

HWTEST_F(DynamicDeviceManagerUtilTest, DynamicDeviceManagerUtilTest001, TestSize.Level0)
{
    std::string udid;
    bool result = DeviceManagerUtil::GetInstance().GetLocalDeviceUdid(udid);
    EXPECT_NE(result, udid.empty());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS