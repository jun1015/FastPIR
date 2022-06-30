#include "muduo/net/TcpServer.h"
#include "muduo/net/EventLoop.h"
#include "muduo/base/Logging.h"
#include "codec.h"
#include<atomic>
#include<mutex>
#include "../mserver.hpp"
using namespace muduo;
using namespace muduo::net;
class TcpQueryServer
{
public:
    TcpQueryServer(EventLoop* loop, const muduo::net::InetAddress& listenAddr, size_t obj_num, size_t obj_size, bool multi_query = true)
        :m_tcpserver(loop, listenAddr, "query_server"), m_clientid(0), m_multiquery(multi_query), m_codec(std::bind(&TcpQueryServer::onQueryMessage, this, _1, _2, _3))
    {
        FastPIRParams params(obj_num, obj_size, 8192, 40);
        m_server.reset(new Mserver(params));
        m_tcpserver.setConnectionCallback(std::bind(&TcpQueryServer::onConnection, this, _1));
        m_tcpserver.setMessageCallback(std::bind(&QueryCodeC::onMessage, m_codec, _1, _2, _3));
    }
    void onConnection(const TcpConnectionPtr& conn)
    {
        if(conn->connected())
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            conn->setContext(m_clientid);
            LOG_INFO << "query client " << conn->peerAddress().toIpPort() << " is connected, id = " << m_clientid++;
        }
        else
        {
            LOG_INFO << "query client " << conn->peerAddress().toIpPort() << " is disconnected, id = " << boost::any_cast<uint32_t>(conn->getContext());
        }
    }
    void onQueryMessage(const TcpConnectionPtr& conn, const std::string& query, Timestamp receiveTime)
    {
        //1. 发送key   2. 发送查询(查询+偏移)
        
        if(m_server->get_key(boost::any_cast<uint32_t>(conn->getContext())) == nullptr)          //需要key
        {
            std::stringstream ss;
            ss << query;
            seal::GaloisKeys gk;
            if(gk.load(m_server->getContext(), ss) == -1)
            {
                LOG_INFO << "client msg error, address = " << conn->peerAddress().toIpPort(); 
                conn->forceClose();
            }
            m_server->set_client_galois_keys(boost::any_cast<uint32_t>(conn->getContext()), gk);
        }
        else
        {       //发查询的情况 因为一个查询可能很大，那么tcp一次接收肯定接收不了，需要设计一个简单的decoder，这里处理的是decoder完之后的消息
            //multi_query / query
            std::shared_ptr<Buffer> buf;
            buf.reset(new Buffer);
            buf->append(query);

            int32_t queryCount = buf->peekInt32(); 
            buf->retrieveInt32();

            queryCount = sockets::networkToHost32(queryCount);
            LOG_INFO << "client " << boost::any_cast<uint32_t>(conn->getContext()) << " query count = " << queryCount;  
            assert(queryCount > 0);

            std::vector<int> indexOffset(queryCount - 1);
            std::vector<int> coeffOffset(queryCount - 1);
            for(int i = 0; i < queryCount - 1; ++i)
            {
                indexOffset[i] = sockets::networkToHost32(buf->peekInt32());
                buf->retrieveInt32();
                coeffOffset[i] = sockets::networkToHost32(buf->peekInt32());
                buf->retrieveInt32();
            }
            std::stringstream ss;
            // size1 cipherSerlerize1 size2 cipherSerlerize2 ... 
            PIRQuery query(m_server->get_query_ciphertext_count());
            for(int i = 0; i < m_server->get_query_ciphertext_count(); i++)
            {
                int serSize = buf->peekInt32();
                buf->retrieveInt32();
                ss << buf->retrieveAsString(sockets::networkToHost32(serSize));
                seal::Ciphertext cipher;
                if(cipher.load(m_server->getContext(), ss) == -1)
                {
                    LOG_INFO << "client msg error, address = " << conn->peerAddress().toIpPort() << " id = " << boost::any_cast<uint32_t>(conn->getContext()); 
                    conn->forceClose();
                }
                query[i] = cipher;
            }
            Query q;
            q.query = query;
            q.indexOffset = indexOffset;
            q.coeffOffset = coeffOffset;
            PIRReply reply = m_server->get_multi_response(boost::any_cast<uint32_t>(conn->getContext()), q);            //generate reply
            std::vector<std::stringstream> replyStream(reply.size());
            for(int i = 0; i < reply.size(); ++i)
            {
                if(reply[i].save(replyStream[i]) == -1)
                {
                    LOG_INFO << "reply error, address = " << conn->peerAddress().toIpPort() << "id = " << boost::any_cast<uint32_t>(conn->getContext()); 
                    conn->forceClose();
                }
            }
            m_codec.send(conn, replyStream);
        }
    }
    void start()
    {
        LOG_INFO << "prepare db ...";
        m_server->set_db(generate_db());
        m_server->preprocess_db();
        LOG_INFO << "server started ";
        m_tcpserver.start();
    }
    std::vector<std::vector<unsigned char>> generate_db()
    {
        int num_obj = m_server->get_num_obj();
        int obj_size = m_server->get_obj_size();
        std::vector<std::vector<unsigned char>> db(num_obj, std::vector<unsigned char>(obj_size));
        //db[i][j] = (i + j) % 256 便于客户端验证是否查询正确
        for(int i = 0; i < num_obj; ++i)
        {
            for(int j = 0; j < obj_size; ++j)
            {
                db[i][j] = (unsigned char)((i + j) % 256);
            }
        }
        return db;
    }

    /*
    struct client_info                  //缓存用户连接信息 暂时不支持缓存查询向量
    {
        uint64_t id;

    };
    */
private:
    QueryCodeC m_codec;
    std::shared_ptr<Mserver> m_server;
    TcpServer m_tcpserver;
    uint32_t m_clientid;           //自增，client_id
    std::mutex m_mutex;
    bool m_multiquery;
};

int main(int argc, char** argv)
{
    int port = 8464;
    EventLoop loop;
    InetAddress addr(port);
    TcpQueryServer server(&loop, addr, 1000, 288);
    server.start();
    loop.loop();
}