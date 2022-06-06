#include "mserver.hpp"

Mserver::Mserver(FastPIRParams params)
{
    context = new seal::SEALContext(params.get_seal_params());      //Seal加密参数都被写死
    N = params.get_poly_modulus_degree();
    plain_bit_count = params.get_plain_modulus_size();

    evaluator = new seal::Evaluator(*context);
    batch_encoder = new seal::BatchEncoder(*context);

    this->num_obj = params.get_num_obj();
    this->obj_size = params.get_obj_size();

    num_query_ciphertext = params.get_num_query_ciphertext();
    num_columns_per_obj = params.get_num_columns_per_obj();
    db_rows = params.get_db_rows();
    db_preprocessed = false;
    reply_ciphertext_num = params.get_reply_ciphertext_num();
}

void Mserver::set_client_galois_keys(uint32_t client_id, seal::GaloisKeys gal_keys)
{
    client_galois_keys[client_id] = gal_keys;
}

void Mserver::encode_db(std::vector<std::vector<uint64_t>> db)
{
    encoded_db = std::vector<seal::Plaintext>(db.size());       //编码成明文
    for (int i = 0; i < db.size(); i++)
    {
        batch_encoder->encode(db[i], encoded_db[i]);
    }
}

void Mserver::set_db(std::vector<std::vector<unsigned char> > db)
{
    assert(db.size() == num_obj);
    std::vector<std::vector<uint64_t> > extended_db(db_rows);       //明文的总数
    for(int i = 0; i < db_rows;i++) {
        extended_db[i] = std::vector<uint64_t>(N, 1ULL);
    }
    int row_size = N/2;

    for(int i = 0; i < num_obj;i++) {               //处理每一条数据
        std::vector<uint64_t> temp = encode(db[i]);     //返回的结果是将一条消息分成两个部分，每个部分占这个向量的一半

        int row = (i / row_size);           //该消息放在第row行密文中
            int col = (i % row_size);        //该消息放在第row行密文的第col 和 col + N/2 个位置
            for (int j = 0; j < num_columns_per_obj / 2; j++)               //放在每一列的相应位置
            {
                extended_db[row][col] = temp[j];
                extended_db[row][col+row_size] = temp[j+(num_columns_per_obj / 2)];
                row += num_query_ciphertext;                        //跳到下一行
            }

    }   
    encode_db(extended_db);
    return;
}


void Mserver::preprocess_db()
{
    if (encoded_db.size() == 0)
    {
        std::cout << "db not set! preprocess failed!" <<std::endl;
        exit(1);
    }
    if (db_preprocessed)
        return;
    auto pid = context->first_parms_id();
    for (int i = 0; i < encoded_db.size(); i++)
    {
        evaluator->transform_to_ntt_inplace(encoded_db[i], pid);            //NTT方法，有利于多项式计算
    }
    db_preprocessed = true;
}

PIRReply Mserver::get_response(uint32_t client_id, PIRQuery query)
{
    if (query.size() != num_query_ciphertext)
    {
        std::cout << "query size doesn't match" <<std::endl;
        exit(1);
    }
    seal::Ciphertext result;
    preprocess_query(query);
    if (!db_preprocessed)
    {
        preprocess_db();
    }

    seal::GaloisKeys gal_keys = client_galois_keys[client_id];
    PIRReply response(reply_ciphertext_num);

    for(size_t i = 0; i < reply_ciphertext_num; ++i)
    {
        assert(i != reply_ciphertext_num - 1 || (i+1)*(N/2) >= num_columns_per_obj/2);
        auto temp = get_sum(query, gal_keys, i * (N/2), (i+1)*(N/2) - 1 <= num_columns_per_obj / 2 - 1 ? (i+1)*(N/2) - 1 : num_columns_per_obj/2-1);
        response[i] = temp;
    }
    return response;
}

seal::Ciphertext Mserver::get_sum(std::vector<seal::Ciphertext> &query, seal::GaloisKeys &gal_keys, uint32_t start, uint32_t end)
{
    seal::Ciphertext result;                    //把所有的行(我们把所有的查询向量当作一行，放一个完整的数据的组当成一列)

    if (start != end)
    {
        int count = (end - start) + 1;                          //需要查询的明文数量
        int next_power_of_two = get_next_power_of_two(count);
        int mid = next_power_of_two / 2;
        seal::Ciphertext left_sum = get_sum(query, gal_keys, start, start + mid - 1);           //递归计算
        seal::Ciphertext right_sum = get_sum(query, gal_keys, start + mid, end);                //算出两个
        evaluator->rotate_rows_inplace(right_sum, -mid, gal_keys);          //旋转、相加(旋转算法)
        evaluator->add_inplace(left_sum, right_sum);
        return left_sum;
    }
    else
    {           //递归结束，只在行明文中查

        seal::Ciphertext column_sum;
        seal::Ciphertext temp_ct;
        evaluator->multiply_plain(query[0], encoded_db[num_query_ciphertext * start], column_sum);      //初始化

        for (int j = 1; j < num_query_ciphertext; j++)              
        {
            evaluator->multiply_plain(query[j], encoded_db[num_query_ciphertext * start + j], temp_ct);
            evaluator->add_inplace(column_sum, temp_ct);
        }           //column_sum是求出的单个明文的计算结果
        evaluator->transform_from_ntt_inplace(column_sum);
        return column_sum;
    }
}

uint32_t Mserver::get_next_power_of_two(uint32_t number)
{
    if (!(number & (number - 1)))
    {
        return number;
    }

    uint32_t number_of_bits = get_number_of_bits(number);
    return (1 << number_of_bits);
}

void Mserver::preprocess_query(std::vector<seal::Ciphertext> &query)
{
    for (int i = 0; i < query.size(); i++)
    {
        evaluator->transform_to_ntt_inplace(query[i]);
    }

    return;
}

uint32_t Mserver::get_number_of_bits(uint64_t number)
{
    uint32_t count = 0;
    while (number)
    {
        count++;
        number /= 2;
    }
    return count;
}

std::vector<uint64_t> Mserver::encode(std::vector<unsigned char> str){       //将bit转换成uint64
    std::vector<uint64_t> res;
    std::string bit_str;
    int plain_data_bits = plain_bit_count - 1;                          //数据=明文模位数 - 1
    int n = str.size();
    int remain = ((n/2)*8)%plain_data_bits;                             //放不满一个系数的数据位数剩余，因为要分到2个部分，所以/2
    for(int iter = 0; iter < 2;iter++) {
        int start_byte = iter * (n/2);
        for (int i=0; i<n/2; i++) {
            bit_str += std::bitset<8>(str[start_byte + i]).to_string();         //将单条消息的每个部分用位表示
        }
        if (remain != 0){
            for (int i=0; i<(plain_data_bits - remain); i++)
                bit_str += "1";                                                 //剩余部分填满
        }
    }   
    for (int i=0; i<bit_str.length(); i+=plain_data_bits)
        res.push_back((uint64_t)std::stoi(bit_str.substr(i,plain_data_bits), nullptr, 2));          //将str按uint64t放到结果中，每次取plain_data_bits位
    //这样将数据分成两份，放到vector<uint64>中，就可以直接放到明文系数中了
    return res;
}