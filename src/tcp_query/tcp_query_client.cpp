#include "muduo/base/Logging.h"
#include "muduo/base/Mutex.h"
#include "muduo/net/EventLoopThread.h"
#include "muduo/net/EventLoop.h"
#include "muduo/net/TcpClient.h"
#include "codec.h"
#include "../mclient.hpp"
#include <iostream>
using namespace muduo;
using namespace muduo::net;
class TcpQueryClient
{
public:
    TcpQueryClient(EventLoop* loop, const InetAddress& address, size_t obj_num, size_t obj_size)
        :m_tcpclient(loop, address, "query client"), m_codec(std::bind(&TcpQueryClient::onReplyMessage, this, _1))
    {
        FastPIRParams params(obj_num, obj_size, 8192, 40);
        m_client.reset(new Mclient(params));
        m_tcpclient.setConnectionCallback(std::bind(&TcpQueryClient::onConnction, this, _1));
        m_tcpclient.setMessageCallback(std::bind(&ReplyCodec::onMessage, m_codec, _1, _2, _3));
        m_tcpclient.enableRetry();
    }

    void connect()
    {
        m_tcpclient.connect();
    }

    void disconnect()
    {
        m_tcpclient.disconnect();
    }
    bool isConnected() 
    {
        return m_connection->connected();
    }
    void onConnction(const TcpConnectionPtr& conn)
    {
        if(conn->connected())
        {
            m_connection = conn;
            sendKey();
            query();
        }
        else
            m_connection.reset();
        LOG_INFO << "connection " << (conn->connected() ? "UP" : "DOWN");
    }

    void onReplyMessage(const std::vector<std::string>& replyStreams)
    {
        std::vector<seal::Ciphertext> ciphers(replyStreams.size());
        for(int i = 0; i < ciphers.size(); ++i)
        {
            std::stringstream temp;
            temp << replyStreams[i];
            if(ciphers[i].load(*(m_client->getContext()), temp) == -1)
            {
                LOG_INFO << "reply error, reply index = " << i;
                m_connection->forceClose(); 
                return;
            }
        }
        auto result = m_client->decode_response(ciphers, m_index[0], m_index.size());
        checkResult(result);
    }
    void sendKey()
    {
        auto key = m_client->get_galois_keys();
        std::stringstream ss;
        key.save(ss);
        m_codec.sendKey(m_connection, ss.str());
    }

    void query()
    {
        int N = m_client->get_poly_degree();
        //m_index = index;
        std::vector<int> indexOffsets(m_index.size() - 1);
        std::vector<int> coeffOffsets(m_index.size() - 1);
        for(int i = 1; i < m_index.size(); ++i)
        {
            indexOffsets[i - 1] = m_index[i] / (N / 2) - m_index[0] / (N / 2);  
            coeffOffsets[i - 1] = -(m_index[i] %  (N / 2) - m_index[0] % (N / 2));
        }
        std::vector<std::string> strQuery;
        auto query = m_client->gen_query(m_index[0]);
        for(int i = 0; i < query.query.size(); ++i)
        {
            std::stringstream temp;
            if(query.query[i].save(temp) == -1)
            {
                LOG_INFO << "construct query stream failed, query index = " << m_index[0];
                m_connection->forceClose();
                return;
            }
            strQuery.push_back(temp.str());
        }
        assert(m_client->get_num_query_ciphertext() == strQuery.size());
        m_codec.send(m_connection, indexOffsets, coeffOffsets, strQuery);
    }

    void checkResult(const std::vector<unsigned char>& result)
    {
        int obj_size = m_client->get_obj_size();
        for(size_t i = 0; i < m_index.size(); ++i)
        {
            for(size_t j = 0; j < obj_size; ++j)
            {
                if(result[i * obj_size + j] != (m_index[i] + j) % 256)
                {
                    LOG_INFO << "result error! index = " << i << " offset = " << j << "query index = " << m_index[i];
                    return;
                }
            }
        }
        LOG_INFO << "result correct! query indexs = ";
        for(auto& i : m_index)
        {
            LOG_INFO << i;
        }
    }

    void setIndex(const std::vector<int>& index)
    {
        m_index = index;
    }
private:
    EventLoop* m_loop;
    EventLoopThread m_threadloop; 
    TcpClient m_tcpclient;
    TcpConnectionPtr m_connection;
    ReplyCodec m_codec;
    std::shared_ptr<Mclient> m_client;
    std::vector<int> m_index;
    
};

void print_usage()
{
    std::cout << "usage: -n <number of objects> -s <object size in bytes>  -a <ip address>  -p <port> -t <query count>" << std::endl;
}

std::vector<int> generate_query(int query_count, int num_obj)
{
    std::vector<int> query(query_count);
    for(int i = 0; i < query_count; ++i)
    {
        query[i] = rand() % num_obj;
    }
    return query;
}

int main(int argc, char** argv)
{
    const char *optstring = "n:s:a:p:t:";
    int option;
    std::string ip;
    int port;
    int query_count;
    int num_obj;
    int obj_size;
    while ((option = getopt(argc, argv, optstring)) != -1)
    {
        switch (option)
        {
        case 'a':
            ip = optarg;
            break;
        case 'p':
            port = std::stoi(optarg);
            break;
        case 't':
            query_count = std::stoi(optarg);
            break;
        case 'n':
            num_obj = std::stoi(optarg);
            break;
        case 's':
            obj_size = std::stoi(optarg);
            break;
        case '?':
            print_usage();
            return 1;
        }
    }

    EventLoop loop;
    InetAddress serverAddress(ip, port);
    TcpQueryClient client(&loop, serverAddress, 1000, 288);
    client.connect();
    std::vector<int> querys = generate_query(query_count, num_obj);
    client.setIndex(querys);
    loop.loop();
    
}

