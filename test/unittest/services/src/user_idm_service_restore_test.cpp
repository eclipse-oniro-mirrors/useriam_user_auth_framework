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

#include "user_idm_service_restore_test.h"

#include <fcntl.h>
#include <future>
#include <sys/stat.h>
#include <unistd.h>

#include "attributes.h"
#include "iam_common_defines.h"
#include "iam_ptr.h"
#include "nlohmann/json.hpp"
#include "mock_ipc_common.h"
#include "mock_resource_node.h"
#include "mock_user_auth_engine.h"
#include "mock_user_idm_callback.h"
#include "mock_user_idm_database.h"
#include "resource_node_pool.h"
#include "thread_handler.h"
#include "user_auth_engine.h"
#include "user_idm_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

namespace {
// RAII guard: redirects UserIdmDatabase::Instance() to a mock for the test scope,
// restoring the real instance on destruction.
class UserIdmDatabaseInstanceGuard {
public:
    explicit UserIdmDatabaseInstanceGuard(UserIdmDatabase &db)
    {
        UserIdmDatabase::SetInstanceForTesting(&db);
    }
    ~UserIdmDatabaseInstanceGuard()
    {
        UserIdmDatabase::ResetInstanceForTesting();
    }
};

void DrainIdmSerialThread()
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    ASSERT_NE(handler, nullptr);
    handler->EnsureTask([]() {});
}

// Build a valid clone-info json array string with the given userId, udid and token.
std::string BuildCloneInfoJson(int32_t userId, const std::string &udid, const std::string &token)
{
    nlohmann::json arr = nlohmann::json::array();
    nlohmann::json idItem;
    idItem["type"] = "userId";
    idItem["detail"] = std::to_string(userId);
    arr.push_back(idItem);
    nlohmann::json udidItem;
    udidItem["type"] = "udid";
    udidItem["detail"] = udid;
    arr.push_back(udidItem);
    nlohmann::json tokenItem;
    tokenItem["type"] = "token";
    tokenItem["detail"] = token;
    arr.push_back(tokenItem);
    return arr.dump();
}

// Build a 64-char udid string.
std::string BuildUdidString()
{
    return std::string(64, 'a');
}

// Write a vector<uint8_t> into a tmpfile and return its fd.
int WriteDataToTmpFile(const std::vector<uint8_t> &data)
{
    int fd = open("/data/local/tmp", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return -1;
    }
    size_t remaining = data.size();
    const uint8_t *ptr = data.data();
    while (remaining > 0) {
        ssize_t written = write(fd, ptr, remaining);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        ptr += written;
        remaining -= static_cast<size_t>(written);
    }
    lseek(fd, 0, SEEK_SET);
    return fd;
}
} // namespace

void UserIdmServiceRestoreTest::SetUpTestCase()
{
}

void UserIdmServiceRestoreTest::TearDownTestCase()
{
}

void UserIdmServiceRestoreTest::SetUp()
{
    MockUserAuthEngine::Holder::GetInstance().Reset();
}

void UserIdmServiceRestoreTest::TearDown()
{
    DrainIdmSerialThread();
    MockUserAuthEngine::Holder::GetInstance().Reset();
}

// OnExtension with unknown extension name returns GENERAL_ERROR.
HWTEST_F(UserIdmServiceRestoreTest, OnExtensionUnknownExtension, TestSize.Level0)
{
    UserIdmService service(123123, true);
    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = service.OnExtension("unknown_extension", data, reply);
    EXPECT_EQ(ret, GENERAL_ERROR);
    int32_t replyVal = 0;
    EXPECT_TRUE(reply.ReadInt32(replyVal));
    EXPECT_EQ(replyVal, GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

// OnExtension dispatches to backup.
HWTEST_F(UserIdmServiceRestoreTest, OnExtensionBackup, TestSize.Level0)
{
    UserIdmService service(123123, true);
    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    MessageParcel data;
    MessageParcel reply;
    // invalid json -> ParseCloneInfo fails -> OnBackup returns GENERAL_ERROR
    data.WriteString("not_a_json");
    int32_t ret = service.OnExtension("backup", data, reply);
    EXPECT_EQ(ret, GENERAL_ERROR);
    int32_t replyVal = 0;
    EXPECT_TRUE(reply.ReadInt32(replyVal));
    EXPECT_EQ(replyVal, GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

// OnExtension dispatches to restore.
HWTEST_F(UserIdmServiceRestoreTest, OnExtensionRestore, TestSize.Level0)
{
    UserIdmService service(123123, true);
    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    MessageParcel data;
    MessageParcel reply;
    // no valid file descriptor -> ReadCloneDataFromFile fails
    int32_t ret = service.OnExtension("restore", data, reply);
    EXPECT_EQ(ret, GENERAL_ERROR);
    int32_t replyVal = 0;
    EXPECT_TRUE(reply.ReadInt32(replyVal));
    EXPECT_EQ(replyVal, GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

// ParseCloneInfo with invalid json string.
HWTEST_F(UserIdmServiceRestoreTest, ParseCloneInfoInvalidJson, TestSize.Level0)
{
    UserIdmService service(123123, true);
    MessageParcel data;
    data.WriteString("invalid_json");
    int32_t userId = 0;
    std::vector<uint8_t> peerUdid;
    std::vector<uint8_t> token;
    int32_t ret = service.ParseCloneInfo(data, userId, peerUdid, token);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

// ParseCloneInfo with non-array json.
HWTEST_F(UserIdmServiceRestoreTest, ParseCloneInfoNonArray, TestSize.Level0)
{
    UserIdmService service(123123, true);
    MessageParcel data;
    data.WriteString("{}");
    int32_t userId = 0;
    std::vector<uint8_t> peerUdid;
    std::vector<uint8_t> token;
    int32_t ret = service.ParseCloneInfo(data, userId, peerUdid, token);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

// ParseCloneInfo with bad userId (non-numeric detail).
HWTEST_F(UserIdmServiceRestoreTest, ParseCloneInfoBadUserId, TestSize.Level0)
{
    UserIdmService service(123123, true);
    nlohmann::json arr = nlohmann::json::array();
    nlohmann::json idItem;
    idItem["type"] = "userId";
    idItem["detail"] = "not_a_number";
    arr.push_back(idItem);
    MessageParcel data;
    data.WriteString(arr.dump());
    int32_t userId = 0;
    std::vector<uint8_t> peerUdid;
    std::vector<uint8_t> token;
    int32_t ret = service.ParseCloneInfo(data, userId, peerUdid, token);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

// ParseCloneInfo with missing udid (bad size).
HWTEST_F(UserIdmServiceRestoreTest, ParseCloneInfoMissingUdid, TestSize.Level0)
{
    UserIdmService service(123123, true);
    nlohmann::json arr = nlohmann::json::array();
    nlohmann::json idItem;
    idItem["type"] = "userId";
    idItem["detail"] = "100";
    arr.push_back(idItem);
    MessageParcel data;
    data.WriteString(arr.dump());
    int32_t userId = 0;
    std::vector<uint8_t> peerUdid;
    std::vector<uint8_t> token;
    int32_t ret = service.ParseCloneInfo(data, userId, peerUdid, token);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

// ParseCloneInfo with invalid userId (no userId entry).
HWTEST_F(UserIdmServiceRestoreTest, ParseCloneInfoInvalidUserId, TestSize.Level0)
{
    UserIdmService service(123123, true);
    nlohmann::json arr = nlohmann::json::array();
    nlohmann::json udidItem;
    udidItem["type"] = "udid";
    udidItem["detail"] = BuildUdidString();
    arr.push_back(udidItem);
    MessageParcel data;
    data.WriteString(arr.dump());
    int32_t userId = INVALID_USER_ID;
    std::vector<uint8_t> peerUdid;
    std::vector<uint8_t> token;
    int32_t ret = service.ParseCloneInfo(data, userId, peerUdid, token);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

// ParseCloneInfo success.
HWTEST_F(UserIdmServiceRestoreTest, ParseCloneInfoSuccess, TestSize.Level0)
{
    UserIdmService service(123123, true);
    const int32_t testUserId = 100;
    const std::string testUdid = BuildUdidString();
    const std::string testToken = "token_value";
    MessageParcel data;
    data.WriteString(BuildCloneInfoJson(testUserId, testUdid, testToken));
    int32_t userId = 0;
    std::vector<uint8_t> peerUdid;
    std::vector<uint8_t> token;
    int32_t ret = service.ParseCloneInfo(data, userId, peerUdid, token);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(userId, testUserId);
    EXPECT_EQ(peerUdid.size(), testUdid.size());
    EXPECT_EQ(token.size(), testToken.size());
}

// ParseCloneInfo skips items with missing keys / wrong types.
HWTEST_F(UserIdmServiceRestoreTest, ParseCloneInfoSkipInvalidItems, TestSize.Level0)
{
    UserIdmService service(123123, true);
    nlohmann::json arr = nlohmann::json::array();
    // item without type/detail keys - skipped
    nlohmann::json emptyItem;
    emptyItem["foo"] = "bar";
    arr.push_back(emptyItem);
    // item with non-string type/detail - skipped
    nlohmann::json wrongTypeItem;
    wrongTypeItem["type"] = 1;
    wrongTypeItem["detail"] = 2;
    arr.push_back(wrongTypeItem);
    // valid userId entry
    nlohmann::json idItem;
    idItem["type"] = "userId";
    idItem["detail"] = "200";
    arr.push_back(idItem);
    // valid udid entry
    nlohmann::json udidItem;
    udidItem["type"] = "udid";
    udidItem["detail"] = BuildUdidString();
    arr.push_back(udidItem);
    MessageParcel data;
    data.WriteString(arr.dump());
    int32_t userId = 0;
    std::vector<uint8_t> peerUdid;
    std::vector<uint8_t> token;
    int32_t ret = service.ParseCloneInfo(data, userId, peerUdid, token);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(userId, 200);
    EXPECT_EQ(peerUdid.size(), 64);
}

// WriteCloneDataToFile with empty data returns SUCCESS.
HWTEST_F(UserIdmServiceRestoreTest, WriteCloneDataToFileEmpty, TestSize.Level0)
{
    UserIdmService service(123123, true);
    MessageParcel reply;
    std::vector<uint8_t> emptyData;
    int32_t ret = service.WriteCloneDataToFile(emptyData, reply);
    EXPECT_EQ(ret, SUCCESS);
}

// WriteCloneDataToFile success writes fd into reply.
HWTEST_F(UserIdmServiceRestoreTest, WriteCloneDataToFileSuccess, TestSize.Level0)
{
    UserIdmService service(123123, true);
    MessageParcel reply;
    std::vector<uint8_t> testData = {1, 2, 3, 4, 5};
    int32_t ret = service.WriteCloneDataToFile(testData, reply);
    EXPECT_EQ(ret, SUCCESS);
    int fd = reply.ReadFileDescriptor();
    EXPECT_GE(fd, 0);
    close(fd);
}

// ReadCloneDataFromFile with invalid fd (ReadFileDescriptor returns -1).
HWTEST_F(UserIdmServiceRestoreTest, ReadCloneDataFromFileInvalidFd, TestSize.Level0)
{
    UserIdmService service(123123, true);
    MessageParcel data;
    // no file descriptor written -> ReadFileDescriptor returns invalid fd
    std::vector<uint8_t> cloneData;
    int32_t ret = service.ReadCloneDataFromFile(data, cloneData, 1024);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

// ReadCloneDataFromFile success.
HWTEST_F(UserIdmServiceRestoreTest, ReadCloneDataFromFileSuccess, TestSize.Level0)
{
    UserIdmService service(123123, true);
    std::vector<uint8_t> testData = {10, 20, 30, 40, 50};
    int fd = WriteDataToTmpFile(testData);
    ASSERT_GE(fd, 0);
    MessageParcel data;
    EXPECT_TRUE(data.WriteFileDescriptor(fd));
    std::vector<uint8_t> cloneData;
    int32_t ret = service.ReadCloneDataFromFile(data, cloneData, 1024);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(cloneData, testData);
    close(fd);
}

// ReadCloneDataFromFile exceeds max size.
HWTEST_F(UserIdmServiceRestoreTest, ReadCloneDataFromFileExceedMax, TestSize.Level0)
{
    UserIdmService service(123123, true);
    std::vector<uint8_t> testData(10, 0xAb);
    int fd = WriteDataToTmpFile(testData);
    ASSERT_GE(fd, 0);
    MessageParcel data;
    EXPECT_TRUE(data.WriteFileDescriptor(fd));
    std::vector<uint8_t> cloneData;
    int32_t ret = service.ReadCloneDataFromFile(data, cloneData, 4);
    EXPECT_EQ(ret, GENERAL_ERROR);
    close(fd);
}

// BuildBackupExtraIn with oversized executorMsg returns empty Attributes.
HWTEST_F(UserIdmServiceRestoreTest, BuildBackupExtraInOversized, TestSize.Level0)
{
    UserIdmService service(123123, true);
    const int32_t testUserId = 100;
    std::vector<uint8_t> peerUdid(64, 'a');
    std::vector<uint8_t> executorMsg(1025, 0x01);
    Attributes result = service.BuildBackupExtraIn(testUserId, peerUdid, executorMsg);
    int32_t userIdOut = INVALID_USER_ID;
    EXPECT_FALSE(result.GetInt32Value(Attributes::ATTR_USER_ID, userIdOut));
}

// BuildBackupExtraIn success.
HWTEST_F(UserIdmServiceRestoreTest, BuildBackupExtraInSuccess, TestSize.Level0)
{
    UserIdmService service(123123, true);
    const int32_t testUserId = 100;
    std::vector<uint8_t> peerUdid(64, 'a');
    std::vector<uint8_t> executorMsg = {1, 2, 3};
    Attributes result = service.BuildBackupExtraIn(testUserId, peerUdid, executorMsg);
    int32_t userIdOut = 0;
    EXPECT_TRUE(result.GetInt32Value(Attributes::ATTR_USER_ID, userIdOut));
    EXPECT_EQ(userIdOut, testUserId);
}

// OnRestoreInner with invalid inner data (empty attributes).
HWTEST_F(UserIdmServiceRestoreTest, OnRestoreInnerInvalidInnerData, TestSize.Level0)
{
    UserIdmService service(123123, true);
    const int32_t testUserId = 100;
    std::vector<uint8_t> peerUdid(64, 'a');
    std::vector<uint8_t> invalidInnerData = {0, 1, 2, 3};
    int32_t ret = service.OnRestoreInner(testUserId, PRIVATE_PIN, peerUdid, invalidInnerData);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

// OnRestoreInner with OpenSession failure returns GENERAL_ERROR.
HWTEST_F(UserIdmServiceRestoreTest, OnRestoreInnerOpenSessionFail, TestSize.Level0)
{
    UserIdmService service(123123, true);
    const int32_t testUserId = 100;
    std::vector<uint8_t> peerUdid(64, 'a');
    Attributes innerAttr = {};
    innerAttr.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, std::vector<uint8_t>{0x10, 0x20});
    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    ASSERT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, OpenSession(_, _)).WillOnce(Return(GENERAL_ERROR));
    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    int32_t ret = service.OnRestoreInner(testUserId, PRIVATE_PIN, peerUdid, innerAttr.Serialize());
    EXPECT_EQ(ret, GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

// OnBackupInner with no enrolled credential returns SUCCESS.
HWTEST_F(UserIdmServiceRestoreTest, OnBackupInnerNotEnrolled, TestSize.Level0)
{
    UserIdmService service(123123, true);
    MockUserIdmDatabase mockDb;
    UserIdmDatabaseInstanceGuard guard(mockDb);
    const int32_t testUserId = 100;
    EXPECT_CALL(mockDb, GetCredentialInfo(testUserId, PRIVATE_PIN, _))
        .WillOnce([](int32_t, AuthType, std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos) {
            credInfos.clear();
            return SUCCESS;
        });
    Attributes extraIn;
    Attributes extraOut;
    int32_t ret = service.OnBackupInner(testUserId, PRIVATE_PIN, extraIn, extraOut);
    EXPECT_EQ(ret, SUCCESS);
    std::vector<uint8_t> cloneData;
    EXPECT_FALSE(extraOut.GetUint8ArrayValue(Attributes::ATTR_CLONE_PRIVATE_PIN_INFO, cloneData));
}

// OnBackupInner with GetCredentialInfo failure returns SUCCESS (no enrollment).
HWTEST_F(UserIdmServiceRestoreTest, OnBackupInnerGetCredFail, TestSize.Level0)
{
    UserIdmService service(123123, true);
    MockUserIdmDatabase mockDb;
    UserIdmDatabaseInstanceGuard guard(mockDb);
    const int32_t testUserId = 100;
    EXPECT_CALL(mockDb, GetCredentialInfo(testUserId, PRIVATE_PIN, _))
        .WillOnce(Return(GENERAL_ERROR));
    Attributes extraIn;
    Attributes extraOut;
    int32_t ret = service.OnBackupInner(testUserId, PRIVATE_PIN, extraIn, extraOut);
    EXPECT_EQ(ret, SUCCESS);
}

// OnBackupInner with enrolled credential but no executor returns GENERAL_ERROR.
HWTEST_F(UserIdmServiceRestoreTest, OnBackupInnerNoExecutor, TestSize.Level0)
{
    UserIdmService service(123123, true);
    MockUserIdmDatabase mockDb;
    UserIdmDatabaseInstanceGuard guard(mockDb);
    const int32_t testUserId = 100;
    EXPECT_CALL(mockDb, GetCredentialInfo(testUserId, PRIVATE_PIN, _))
        .WillOnce([](int32_t, AuthType, std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos) {
            // non-empty credential list triggers SendCommandToExecutor path
            credInfos.push_back(nullptr);
            return SUCCESS;
        });
    Attributes extraIn;
    Attributes extraOut;
    // no resource node inserted -> SendCommandToExecutor returns GENERAL_ERROR
    int32_t ret = service.OnBackupInner(testUserId, PRIVATE_PIN, extraIn, extraOut);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

// OnBackupInner success with executor registered.
HWTEST_F(UserIdmServiceRestoreTest, OnBackupInnerSuccess, TestSize.Level0)
{
    UserIdmService service(123123, true);
    MockUserIdmDatabase mockDb;
    UserIdmDatabaseInstanceGuard guard(mockDb);
    const int32_t testUserId = 100;
    const uint64_t testExecutorIndex = 600;
    EXPECT_CALL(mockDb, GetCredentialInfo(testUserId, PRIVATE_PIN, _))
        .WillOnce([](int32_t, AuthType, std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos) {
            credInfos.push_back(nullptr);
            return SUCCESS;
        });
    auto resourceNode = Common::MakeShared<MockResourceNode>();
    ASSERT_NE(resourceNode, nullptr);
    EXPECT_CALL(*resourceNode, GetExecutorIndex()).WillRepeatedly(Return(testExecutorIndex));
    EXPECT_CALL(*resourceNode, GetAuthType()).WillRepeatedly(Return(PRIVATE_PIN));
    EXPECT_CALL(*resourceNode, GetExecutorRole()).WillRepeatedly(Return(ALL_IN_ONE));
    EXPECT_CALL(*resourceNode, GetExecutorMatcher()).WillRepeatedly(Return(0));
    EXPECT_CALL(*resourceNode, GetExecutorSensorHint()).WillRepeatedly(Return(0));
    EXPECT_CALL(*resourceNode, GetExecutorPublicKey()).WillRepeatedly(Return(std::vector<uint8_t>()));
    EXPECT_CALL(*resourceNode, SetProperty(_, _))
        .WillOnce([](const Attributes &properties, Attributes &values) {
            std::vector<uint8_t> outData = {0xAA, 0xBB};
            values.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, outData);
            return SUCCESS;
        });
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    Attributes extraIn;
    Attributes extraOut;
    int32_t ret = service.OnBackupInner(testUserId, PRIVATE_PIN, extraIn, extraOut);
    EXPECT_EQ(ret, SUCCESS);
    std::vector<uint8_t> cloneData;
    EXPECT_TRUE(extraOut.GetUint8ArrayValue(Attributes::ATTR_CLONE_PRIVATE_PIN_INFO, cloneData));
    EXPECT_FALSE(cloneData.empty());
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(testExecutorIndex));
    ResourceNodePool::Instance().DeleteAll();
}

// OnBackup with ParseCloneInfo failure.
HWTEST_F(UserIdmServiceRestoreTest, OnBackupParseCloneInfoFail, TestSize.Level0)
{
    UserIdmService service(123123, true);
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("invalid_json");
    int32_t ret = service.OnBackup(data, reply);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

// OnBackup with VerifyAuthToken failure.
HWTEST_F(UserIdmServiceRestoreTest, OnBackupVerifyAuthTokenFail, TestSize.Level0)
{
    UserIdmService service(123123, true);
    const int32_t testUserId = 100;
    MessageParcel data;
    data.WriteString(BuildCloneInfoJson(testUserId, BuildUdidString(), "token"));
    MessageParcel reply;
    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    ASSERT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, VerifyAuthToken(_, _, _, _, _)).WillOnce(Return(GENERAL_ERROR));
    int32_t ret = service.OnBackup(data, reply);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

// OnRestore with ReadCloneDataFromFile failure (no fd).
HWTEST_F(UserIdmServiceRestoreTest, OnRestoreReadFail, TestSize.Level0)
{
    UserIdmService service(123123, true);
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = service.OnRestore(data, reply);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

// OnRestore with ParseCloneInfo failure (valid fd, invalid json).
HWTEST_F(UserIdmServiceRestoreTest, OnRestoreParseCloneInfoFail, TestSize.Level0)
{
    UserIdmService service(123123, true);
    std::vector<uint8_t> cloneData = {1, 2, 3};
    int fd = WriteDataToTmpFile(cloneData);
    ASSERT_GE(fd, 0);
    MessageParcel data;
    EXPECT_TRUE(data.WriteFileDescriptor(fd));
    data.WriteString("invalid_json");
    MessageParcel reply;
    int32_t ret = service.OnRestore(data, reply);
    EXPECT_EQ(ret, GENERAL_ERROR);
    close(fd);
}

// OnRestore with invalid clone data (no ATTR_CLONE_PRIVATE_PIN_INFO).
HWTEST_F(UserIdmServiceRestoreTest, OnRestoreInvalidCloneData, TestSize.Level0)
{
    UserIdmService service(123123, true);
    std::vector<uint8_t> cloneData = {1, 2, 3};
    int fd = WriteDataToTmpFile(cloneData);
    ASSERT_GE(fd, 0);
    MessageParcel data;
    EXPECT_TRUE(data.WriteFileDescriptor(fd));
    data.WriteString(BuildCloneInfoJson(100, BuildUdidString(), "token"));
    MessageParcel reply;
    int32_t ret = service.OnRestore(data, reply);
    EXPECT_EQ(ret, SUCCESS);
    close(fd);
}

// StartRestoreEnroll with OpenSession failure returns GENERAL_ERROR.
HWTEST_F(UserIdmServiceRestoreTest, StartRestoreEnrollOpenSessionFail, TestSize.Level0)
{
    UserIdmService service(123123, true);
    const int32_t testUserId = 100;
    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    ASSERT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, OpenSession(_, _)).WillOnce(Return(GENERAL_ERROR));
    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    auto promise = std::make_shared<std::promise<int32_t>>();
    std::vector<uint8_t> restoreData = {1, 2, 3};
    int32_t ret = service.StartRestoreEnroll(testUserId, PRIVATE_PIN, restoreData, promise);
    EXPECT_EQ(ret, GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

// WaitForRestoreEnrollResult success.
HWTEST_F(UserIdmServiceRestoreTest, WaitForRestoreEnrollResultSuccess, TestSize.Level0)
{
    UserIdmService service(123123, true);
    const int32_t testUserId = 100;
    auto mockHdi = MockUserAuthEngine::Holder::GetInstance().Get();
    ASSERT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, CloseSession(_)).WillRepeatedly(Return(SUCCESS));
    auto promise = std::make_shared<std::promise<int32_t>>();
    std::future<int32_t> future = promise->get_future();
    promise->set_value(SUCCESS);
    int32_t ret = service.WaitForRestoreEnrollResult(testUserId, future);
    EXPECT_EQ(ret, SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
