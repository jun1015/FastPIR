#ifndef __MCODEC_H__
#define __MCODEC_H__
#include "muduo/base/Logging.h"
#include "muduo/net/Buffer.h"
#include "muduo/net/Endian.h"
#include "muduo/net/TcpConnection.h"
#include<sstream>
using namespace muduo;
using namespace muduo::net;
class QueryCodeC
{
public:
    typedef std::function<void (const muduo::net::TcpConnectionPtr&,
                                const std::string& query,
                                muduo::Timestamp)> QueryMessageCallback;
    QueryCodeC(const QueryMessageCallback& cb)
        :m_cb(cb)
        {

        }

    void onMessage(const TcpConnectionPtr& conn, Buffer* buf, Timestamp receiveTime)                        //call onMessage
    {
        while(buf->readableBytes() >= sizeof(uint64_t))
        {
            int64_t count64 = buf->peekInt64();
            int64_t byteCount = sockets::networkToHost64(count64);
            if(byteCount < 0)
            {
                LOG_INFO << "invalid len: " << byteCount;
                conn->shutdown();
                break;
            }
            else if(byteCount + sizeof(int64_t) <= buf->readableBytes())
            {
                buf->retrieve(sizeof(int64_t));
                std::string msg(buf->peek(), byteCount);
                buf->retrieve(byteCount);
                m_cb(conn, msg, receiveTime);
            }
            else
            {
                break;
            }
        }
    }

    void send(const TcpConnectionPtr& conn, const std::vector<std::stringstream>& serReply)
    {
        Buffer buf;
        for(int i = 0; i < serReply.size(); ++i)            //add size|ciphertext to buffer
        {
            std::string temp = serReply[i].str();
            buf.appendInt32(sockets::hostToNetwork32(temp.size()));
            buf.append(temp.data(), temp.size());
        }
        int64_t len = buf.readableBytes();
        buf.prependInt64(sockets::hostToNetwork64(len));
        conn->send(&buf);
    }
private:
    QueryMessageCallback m_cb;

};

class ReplyCodec
{
public:
    typedef std::function<void (const std::vector<std::string>&)> ReplyCallBack;
    
    ReplyCodec(const ReplyCallBack& cb):m_cb(cb)
    {

    }
    
    void onMessage(const TcpConnectionPtr& conn, Buffer* buf, Timestamp receiveTime)
    {
        // len   sublen1 ciphertext1 sublen2 ciphertext2 ...
        while(buf->readableBytes() >= sizeof(uint64_t))
        {
            int64_t count64 = buf->peekInt64();
            int64_t byteCount = sockets::networkToHost64(count64);
            if(byteCount < 0)
            {
                LOG_ERROR << "invalid reply count: " << byteCount;
                conn->shutdown();
                break;
            }
            if(buf->readableBytes() >= sizeof(uint64_t) + byteCount)
            {
                buf->retrieveInt64();
                std::vector<std::string> replyStream;
                int64_t offset = 0;
                int replyNum = 0;
                while(offset < byteCount)
                {
                    int32_t streamLen = sockets::networkToHost32(buf->peekInt32());
                    buf->retrieveInt32();
                    offset += sizeof(int32_t);
                    offset += streamLen;
                    if(offset > byteCount || buf->readableBytes() < streamLen)
                    {
                        LOG_ERROR << "invalid reply stream count, reply num = " << replyNum + 1 << " byteCount = " << byteCount << " readable bytes = " << buf->readableBytes();
                        conn->shutdown();
                        break;
                    }
                    std::string temp = std::string(buf->peek(), streamLen);
                    replyStream.push_back(std::move(temp));
                    buf->retrieve(streamLen);
                }
                m_cb(replyStream);
            }
            else
            {
                break;
            }
        }
    }

    void sendKey(const TcpConnectionPtr& conn, const std::string& gal_key)
    {
        Buffer buf;
        buf.append(gal_key);
        int64_t len = buf.readableBytes();
        buf.prependInt64(sockets::hostToNetwork64(len));
        conn->send(&buf);
    }

    void send(const TcpConnectionPtr& conn, const std::vector<int>& indexOffset, const std::vector<int>& coeffOffset, const std::vector<std::string>& queryStream)
    {
        Buffer buf;
        buf.appendInt32(sockets::hostToNetwork32(indexOffset.size() + 1));
        for(int i = 0; i < coeffOffset.size(); ++i)
        {
            buf.appendInt32(sockets::hostToNetwork32(indexOffset[i]));
            buf.appendInt32(sockets::hostToNetwork32(coeffOffset[i]));
        }
        
        for(int i = 0; i < queryStream.size(); ++i)
        {
            buf.appendInt32(sockets::hostToNetwork32(queryStream[i].size()));
            buf.append(queryStream[i]);
        }
        int64_t len = buf.readableBytes();
        buf.prependInt64(sockets::hostToNetwork64(len));
        conn->send(&buf);
    }
private:
    ReplyCallBack m_cb;
};

#endif