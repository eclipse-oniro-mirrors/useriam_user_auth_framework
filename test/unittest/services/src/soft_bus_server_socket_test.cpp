/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "soft_bus_server_socket_test.h"
#include "soft_bus_server_socket.h"
#include "soft_bus_manager.h"
#include "remote_connect_listener_manager.h"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void SoftBusServerSocketTest::SetUpTestCase()
{
}

void SoftBusServerSocketTest::TearDownTestCase()
{
}

void SoftBusServerSocketTest::SetUp()
{
}

void SoftBusServerSocketTest::TearDown()
{
}

class ServerSocketTest : public ServerSocket {
public:
    explicit ServerSocketTest(const int32_t socketId);
    ~ServerSocketTest();
    ResultCode SendMessage(const std::string &connectionName, const std::string &srcEndPoint,
        const std::string &destEndPoint, const std::shared_ptr<Attributes> &attributes, MsgCallback &callback);
    void OnBind(int32_t socketId, PeerSocketInfo info) override;
};

ServerSocketTest::ServerSocketTest(const int32_t socketId)
    : ServerSocket(socketId)
{
}

ServerSocketTest::~ServerSocketTest()
{
}

void ServerSocketTest::OnBind(int32_t socketId, PeerSocketInfo info)
{
    return;
}

ResultCode ServerSocketTest::SendMessage(const std::string &connectionName, const std::string &srcEndPoint,
    const std::string &destEndPoint, const std::shared_ptr<Attributes> &attributes, MsgCallback &callback)
{
    return SUCCESS;
}

HWTEST_F(SoftBusServerSocketTest, SoftBusServerSocketTestOnBind, TestSize.Level0)
{
    int32_t socketId = 1;
    ServerSocketTest *serverSocket = new ServerSocketTest(socketId);
    PeerSocketInfo info;
    EXPECT_NO_THROW(serverSocket->OnBind(-2, info));
    delete serverSocket;
}

HWTEST_F(SoftBusServerSocketTest, SoftBusServerSocketTestOnShutdown, TestSize.Level0)
{
    int32_t socketId = 1;
    ServerSocketTest *serverSocket = new ServerSocketTest(socketId);
    const std::string connectionName = "connectionName";
    ShutdownReason reason = SHUTDOWN_REASON_LOCAL;
    serverSocket->AddClientConnection(socketId, connectionName);
    EXPECT_NO_THROW(serverSocket->OnShutdown(socketId, reason));
    EXPECT_NO_THROW(serverSocket->OnShutdown(socketId, reason));
    serverSocket->clientConnectionMap_ = {};
    delete serverSocket;
}

HWTEST_F(SoftBusServerSocketTest, SoftBusServerSocketTestOnBytes, TestSize.Level0)
{
    int32_t socketId = 1;
    ServerSocketTest *serverSocket = new ServerSocketTest(socketId);
    const std::string networkId = "connectionName";
    void *data = new char[10];
    uint32_t dataLen = 10;
    EXPECT_NO_THROW(serverSocket->OnBytes(socketId, data, dataLen));
    EXPECT_NO_THROW(serverSocket->AddServerSocket(socketId, networkId));
    EXPECT_NO_THROW(serverSocket->OnBytes(socketId, data, dataLen));
    serverSocket->serverSocketBindMap_ = {};
    serverSocket->clientConnectionMap_ = {};
    delete serverSocket;
}

HWTEST_F(SoftBusServerSocketTest, SoftBusServerSocketTestAddServerSocket, TestSize.Level0)
{
    int32_t socketId = 1;
    ServerSocketTest *serverSocket = new ServerSocketTest(socketId);
    const std::string networkId = "connectionName";
    EXPECT_NO_THROW(serverSocket->AddServerSocket(socketId, networkId));
    EXPECT_NO_THROW(serverSocket->AddServerSocket(socketId, networkId));
    serverSocket->serverSocketBindMap_ = {};
    delete serverSocket;
}

HWTEST_F(SoftBusServerSocketTest, SoftBusServerSocketTestDeleteServerSocket, TestSize.Level0)
{
    int32_t socketId = 1;
    ServerSocketTest *serverSocket = new ServerSocketTest(socketId);
    const std::string networkId = "connectionName";
    EXPECT_NO_THROW(serverSocket->DeleteServerSocket(socketId));
    EXPECT_NO_THROW(serverSocket->AddServerSocket(socketId, networkId));
    EXPECT_NO_THROW(serverSocket->DeleteServerSocket(socketId));
    delete serverSocket;
}

HWTEST_F(SoftBusServerSocketTest, SoftBusServerSocketTestGetNetworkIdBySocketId, TestSize.Level0)
{
    int32_t socketId = 1;
    ServerSocketTest *serverSocket = new ServerSocketTest(socketId);
    std::string result = serverSocket->GetNetworkIdBySocketId(socketId);
    EXPECT_EQ(result, "");
    const std::string networkId = "connectionName";
    EXPECT_NO_THROW(serverSocket->AddServerSocket(socketId, networkId));
    result = serverSocket->GetNetworkIdBySocketId(socketId);
    EXPECT_EQ(result, networkId);
    serverSocket->serverSocketBindMap_ = {};
    delete serverSocket;
}

HWTEST_F(SoftBusServerSocketTest, SoftBusServerSocketTestAddClientConnection, TestSize.Level0)
{
    int32_t socketId = 1;
    ServerSocketTest *serverSocket = new ServerSocketTest(socketId);
    const std::string connectionName = "connectionName";
    std::string clientConnectionName = serverSocket->GetClientConnectionName(socketId);
    EXPECT_EQ(clientConnectionName, "");
    EXPECT_NO_THROW(serverSocket->AddClientConnection(socketId, connectionName));
    clientConnectionName = serverSocket->GetClientConnectionName(socketId);
    EXPECT_EQ(clientConnectionName, connectionName);
    EXPECT_NO_THROW(serverSocket->AddClientConnection(socketId, connectionName));
    serverSocket->clientConnectionMap_ = {};
    delete serverSocket;
}

HWTEST_F(SoftBusServerSocketTest, SoftBusServerSocketTestDeleteClientConnection, TestSize.Level0)
{
    int32_t socketId = 1;
    ServerSocketTest *serverSocket = new ServerSocketTest(socketId);
    const std::string connectionName = "connectionName";
    EXPECT_NO_THROW(serverSocket->DeleteClientConnection(socketId));
    EXPECT_NO_THROW(serverSocket->AddClientConnection(socketId, connectionName));
    EXPECT_NO_THROW(serverSocket->DeleteClientConnection(socketId));
    serverSocket->clientConnectionMap_ = {};
    delete serverSocket;
}

HWTEST_F(SoftBusServerSocketTest, SoftBusServerSocketTestGetSocketIdByClientConnectionName, TestSize.Level0)
{
    int32_t socketId = 1;
    ServerSocketTest *serverSocket = new ServerSocketTest(socketId);
    const std::string connectionName = "connectionName";
    EXPECT_NO_THROW(serverSocket->AddClientConnection(socketId, connectionName));
    int32_t result = serverSocket->GetSocketIdByClientConnectionName(connectionName);
    ASSERT_EQ(result, socketId);
    const std::string connectionName1 = "connectionName1";
    result = serverSocket->GetSocketIdByClientConnectionName(connectionName1);
    ASSERT_EQ(result, -1);
    serverSocket->clientConnectionMap_ = {};
    delete serverSocket;
}

HWTEST_F(SoftBusServerSocketTest, SoftBusServerSocketTestOnBind01, TestSize.Level0)
{
    int32_t socketId = -2;
    ServerSocket *serverSocket = new ServerSocket(socketId);
    const std::string connectionName = "connectionName";
    PeerSocketInfo info;
    EXPECT_NO_THROW(serverSocket->OnBind(socketId, info));
    socketId = 1;
    const int len = 6;
    std::string networkIdName = "Hello";
    (void)memcpy_s(info.networkId, len, networkIdName.c_str(), networkIdName.size());
    EXPECT_NO_THROW(serverSocket->OnBind(socketId, info));
    delete serverSocket;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
