#include "muduo/base/Logging.h"
#include "muduo/base/Mutex.h"
#include "muduo/net/EventLoopThread.h"
#include "muduo/net/EventLoop.h"
#include "muduo/net/TcpClient.h"
#include "codec.h"
#include "../mclient.hpp"
#include <iostream>
#include <chrono>
using namespace muduo;
using namespace muduo::net;
class TcpQueryClient
{
public:
    TcpQueryClient(EventLoop* loop, const InetAddress& address, size_t obj_num, size_t obj_size, bool multi)
        :m_tcpclient(loop, address, "query client"), m_codec(std::bind(&TcpQueryClient::onReplyMessage, this, _1)), m_multiquery(multi)
    {
        FastPIRParams params(obj_num, obj_size);
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
            time_start = std::chrono::high_resolution_clock::now();
            sendKey();
            if(m_multiquery)
            {
                LOG_INFO << "multi query start";
                query();
            }
            else 
            {
                LOG_INFO << "single query start";
                part_query();
            }
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
        //auto result = m_client->decode_response(ciphers, m_index[0], m_index.size());
        if(m_multiquery)
        {
            auto result = m_client->decode_response(ciphers, m_index[0], m_index.size());
            checkResult(result);
        }
        else
        {
            static int num = 0;
            auto result = m_client->decode_response(ciphers, m_index[num++], 1);
            partCheckResult(result);
        }
        
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

    void part_query()
    {
        for(int i = 0; i < m_index.size(); ++i)
        {
            std::vector<std::string> strQuery;
            auto query = m_client->gen_query(m_index[i]);
            for(int j = 0; j < query.query.size(); ++j)
            {
                std::stringstream temp;
                if(query.query[j].save(temp) == -1)
                {
                    LOG_INFO << "construct query stream failed, query index = " << m_index[i];
                    m_connection->forceClose();
                    return;
                }
                strQuery.push_back(temp.str());
            }
            assert(m_client->get_num_query_ciphertext() == strQuery.size());
            m_codec.send(m_connection, query.indexOffset, query.coeffOffset, strQuery);
            LOG_INFO << "query " << i << " send";
        }
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
                    LOG_INFO << "result error! index = " << i << " offset = " << j << " query index = " << m_index[i];
                    return;
                }
            }
        }
        LOG_INFO << "result correct! query indexs = ";
        for(auto& i : m_index)
        {
            LOG_INFO << i;
        }
        time_end = std::chrono::high_resolution_clock::now();
        LOG_INFO << "num_obj = " << m_client->get_num_obj() << " obj_size = " << m_client->get_obj_size() << " query count = " << m_index.size()
                << " query time = " << (std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start)).count();
    }

    void partCheckResult(const std::vector<unsigned char>& result)
    {
        static int num = 0;
        int obj_size = m_client->get_obj_size();
        int index = m_index[num];
        for(int i = 0; i < obj_size; ++i)
        {
            if(result[i] != (index + i) % 256)
            {
                LOG_INFO << "result error! index = " << num << " offset = " << i << " query index = " << index;
                num++;
                return;
            }
        }
        num++;
        if(num == m_index.size())
        {
            LOG_INFO << "result correct! query indexs = ";
            for(auto& i : m_index)
            {
                LOG_INFO << i;
            }
            time_end = std::chrono::high_resolution_clock::now();
            LOG_INFO << "num_obj = " << m_client->get_num_obj() << " obj_size = " << m_client->get_obj_size() << " query count = " << m_index.size()
                << " query time = " << (std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start)).count();
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
    std::chrono::_V2::system_clock::time_point time_start;
    std::chrono::_V2::system_clock::time_point time_end;
    bool m_multiquery;
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
    const char *optstring = "n:s:a:p:t:m:";
    int option;
    std::string ip;
    int port;
    int query_count;
    int num_obj;
    int obj_size;
    bool multi = false; 
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
        case 'm':
            multi = true;
            break;
        case '?':
            print_usage();
            return 1;
        }
    }

    EventLoop loop;
    InetAddress serverAddress(ip, port);
    TcpQueryClient client(&loop, serverAddress, num_obj, obj_size, multi);
    client.connect();
    std::vector<int> querys = generate_query(query_count, num_obj);
    client.setIndex(querys);
    loop.loop();
    
}

