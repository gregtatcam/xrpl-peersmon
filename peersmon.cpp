#include <Overlay.h>

#include <boost/regex.hpp>
#include <boost/tokenizer.hpp>
#include <unordered_map>

#include <fstream>
#include <iostream>
#include <iterator>

std::vector<std::thread> threads;
boost::asio::io_service io_service;
boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work(
    boost::asio::make_work_guard(io_service));

int
main(int argc, char* argv[])
{
    std::vector<std::string> peers;
    std::unordered_map<int, bool> messagesToLog;
    int numberOfThreads = 8;
    for (int i = 0; i < argc; ++i)
    {
        if (!strcmp(argv[i], "--peers"))
        {
            ++i;
            std::ifstream f(argv[i]);
            if (f.good())
            {
                std::string peer;
                while (f >> peer)
                    peers.push_back(peer);
            }
            else
            {
                typedef boost::tokenizer<boost::char_separator<char>> tokenizer;
                boost::char_separator<char> sep{","};
                auto s = std::string(argv[i]);
                tokenizer tok{s, sep};
                for (auto t : tok)
                    peers.push_back(t);
            }
        }
        else if (!strcmp(argv[i], "--threads"))
        {
            ++i;
            numberOfThreads = std::stoi(argv[i]);
        }
        else if (!strcmp(argv[i], "--messages"))
        {
            ++i;
            typedef boost::tokenizer<boost::char_separator<char>> tokenizer;
            boost::char_separator<char> sep{","};
            auto s = std::string(argv[i]);
            tokenizer tok{s, sep};
            boost::regex rx("^(\\d+)\\-(\\d+)$");
            for (const auto& t : tok)
            {
                boost::smatch match;
                if (boost::regex_search(t, match, rx))
                {
                    for (int i = std::stoi(match[1]); i <= std::stoi(match[2]);
                         ++i)
                        messagesToLog[i] = true;  // might be bogus messages
                }
                else
                    messagesToLog[std::stoi(t)] = true;
            }
        }
    }
    if (peers.empty())
    {
        std::cerr << "peers option must be specified\n";
        return 1;
    }
    threads.reserve(numberOfThreads);

    while (numberOfThreads--)
    {
        threads.emplace_back([&]() { io_service.run(); });
    }

    auto overlay =
        std::make_shared<ripple::Overlay>(io_service, peers, messagesToLog);
    overlay->start();

    work.reset();
    for (auto& t : threads)
        t.join();

    return 0;
}
