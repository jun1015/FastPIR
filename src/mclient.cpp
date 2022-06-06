#include "mclient.hpp"
#include<algorithm>
Mclient::Mclient(FastPIRParams params)
{
    this->num_obj = params.get_num_obj();
    this->obj_size = params.get_obj_size();

    N = params.get_poly_modulus_degree();
    num_columns_per_obj = params.get_num_columns_per_obj();
    plain_bit_count = params.get_plain_modulus_size();
    num_query_ciphertext = params.get_num_query_ciphertext();
    reply_ciphertext_num = params.get_reply_ciphertext_num();

    context = new seal::SEALContext(params.get_seal_params());
    keygen = new seal::KeyGenerator(*context);
    secret_key = keygen->secret_key();
    encryptor = new seal::Encryptor(*context, secret_key);
    decryptor = new seal::Decryptor(*context, secret_key);
    batch_encoder = new seal::BatchEncoder(*context);

    std::vector<int> steps;
    for (int i = 1; i < (num_columns_per_obj / 2) && i < (N / 2); i *= 2)          //最后还是要旋转成单个密文！ 所以说还是有限制，这里可否改进？  
    {
        steps.push_back(-i);
    }
    keygen->create_galois_keys(steps, gal_keys);

    return;
}

PIRQuery Mclient::gen_query(uint32_t index)              //根据index生成查询
{
    std::vector<seal::Ciphertext> query(num_query_ciphertext);          //查询的总数：即数据库每行的明文个数
    seal::Plaintext pt;
    size_t slot_count = batch_encoder->slot_count();
    size_t row_size = slot_count / 2;                                   //分成两部分

    for (int i = 0; i < num_query_ciphertext; i++)
    {
        std::vector<uint64_t> pod_matrix(slot_count, 0ULL);
        if ((index / row_size) == i)                        //一个查询中只有一半的slot计索引
        {
            pod_matrix[index % row_size] = 1;                   //两部分设为1
            pod_matrix[row_size + (index % row_size)] = 1;
        }
        batch_encoder->encode(pod_matrix, pt);                  //编码、加密
        encryptor->encrypt_symmetric(pt, query[i]);
    }

    return query;   
}

std::vector<unsigned char> Mclient::decode_response(std::vector<seal::Ciphertext> response, uint32_t index)
{
    seal::Plaintext pt;
    std::vector<uint64_t> decoded_response;
    size_t row_size = N / 2;
    
    std::vector<std::vector<unsigned char>> charRes; 
    std::vector<unsigned char> res;
    res.resize(obj_size);
    int offset = 0;
    for(auto c = response.begin(); c != response.end(); ++c)
    {
        decryptor->decrypt(*c, pt);
        batch_encoder->decode(pt, decoded_response);
        decoded_response = rotate_plain(decoded_response, index % row_size);
        auto tempMsg = decode(decoded_response, c == response.end() - 1);                //decode直接解明文 
        charRes.push_back(tempMsg);
        //memcpy(res.data() + offset, tempMsg.data(), std::min(tempMsg.size(), res.size() - offset));
        offset+=tempMsg.size();             
    }
    offset = 0;
    int maxPlainSize = std::min((plain_bit_count - 1) * N / (2*8), obj_size / 2);
    for(int i = 0; i < 2; ++i)
    {
        for(int j = 0; j < reply_ciphertext_num; ++j)
        {
            int tempSize = maxPlainSize;
            if(j == reply_ciphertext_num - 1 && tempSize != (obj_size / 2))
            {
                tempSize = (obj_size / 2) % maxPlainSize;
            }
            memcpy(res.data() + offset, charRes[j].data() + i * maxPlainSize, tempSize);
            offset += tempSize;
        }
    }

    return res;
}

seal::GaloisKeys Mclient::get_galois_keys()
{
    return gal_keys;
}

std::vector<uint64_t> Mclient::rotate_plain(std::vector<uint64_t> original, int index)
{
    int sz = original.size();
    int row_count = sz / 2;
    std::vector<uint64_t> result(sz);
    for (int i = 0; i < row_count; i++)
    {
        result[i] = original[(index + i) % row_count];
        result[row_count + i] = original[row_count + ((index + i) % row_count)];
    }

    return result;
}

std::vector<unsigned char> Mclient::decode(std::vector<uint64_t> v, bool last)
{
    int n = v.size();
    const int plain_data_bits = plain_bit_count - 1;
    std::vector<unsigned char> res;
    std::string bit_str;
    for (auto item : v)
    {
        bit_str += std::bitset<PLAIN_BIT>(item).to_string();            //bit_str: 一个明文中的数据按位排
    }
    // 消息是分成两份的， 即第一部分的消息从0开始，第二部分从N/2开始，这样

    //std::vector<unsigned char> res(bit_str.size() / 8);

    /*
    for (int i = 0; i < N / 2; i++)
    {
    }
    int sz = res.size();
    for (int i = 0; i < (sz / 2); i++)              //越界：原本一个明文肯定大于一条消息，现在消息可能大于明文，所以用sz来做不合适
    {
        res[i] = std::bitset<8>(bit_str.substr(i * 8, 8)).to_ulong();
        res[i + (sz / 2)] = std::bitset<8>(bit_str.substr((plain_data_bits * n / 2) + i * 8, 8)).to_ulong();
    }
    */
   /*
    std::vector<unsigned char> res2(obj_size);
    for (int i = 0; i < (obj_size / 2); i++)
    {
        res2[i] = std::bitset<8>(bit_str.substr(i * 8, 8)).to_ulong();
        res2[i + (obj_size / 2)] = std::bitset<8>(bit_str.substr((plain_data_bits * n / 2) + i * 8, 8)).to_ulong();
    }
    */
   //需要把bit_str中的信息按字节全部返回回去
    size_t sz = bit_str.size() / 8;
    
    /*for(int i = 0; i < sz; ++i)
    {
        res.push_back(std::bitset<8>(bit_str.substr(i * 8, 8)).to_ulong());
    }*/
    /*
    if(last)
    {
        res.resize((int)obj_size % (((int)plain_bit_count * n)/8));
    }
    else
    */
    res.resize(std::min((int)obj_size, (int)ceil(bit_str.size() / 8)));
    for(int i = 0; i < res.size() / 2; ++i)
    {
        res[i] = std::bitset<8>(bit_str.substr(i * 8, 8)).to_ulong();
        res[i + (res.size() / 2)] = std::bitset<8>(bit_str.substr((plain_data_bits * n / 2) + i * 8, 8)).to_ulong();
    }


    return res;
}