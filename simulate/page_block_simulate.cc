#include <iostream>
#include <vector>
#include <algorithm>
#include <random>
#include <ctime>
#include <set>
#include <list>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <atomic>
#include <boost/intrusive/list.hpp>

int global_id;
const uint64_t pages_num_per_block = 64;
bool flag = false;



struct Block : public boost::intrusive::list_base_hook<> {
    int total_pages; // 总页面数
    int used_pages;  // 已使用页面数
    int id;

    Block(int total, int id) : total_pages(total), used_pages(0), id(id) {}

    double utilization() const {
        return static_cast<double>(used_pages) / total_pages;
    }

    bool operator<(const Block& other) {
        return used_pages > other.used_pages;
    }

    bool operator==(const Block& other) {
        return this == &other;
    }
};


struct Allocator {
    std::set<Block*> allocable_blocks;
    //std::list<Block*> allocable_blocks_rand;
    boost::intrusive::list<Block> allocable_blocks_rand;
    std::unordered_map<int, Block*> bmap;
    std::mutex allocator_mutex;
    std::atomic<uint64_t> page_alloc;
    std::atomic<uint64_t> block_alloc;
    std::atomic<uint64_t> page_release;
    std::atomic<uint64_t> block_release;

    Allocator() : page_alloc(0), block_alloc(0), page_release(0), block_release(0) {

    }

    int allocate_page_random() {
        page_alloc++;

        Block* b = nullptr;
        if(allocable_blocks_rand.size() == 0) {
            block_alloc++;
            b = new Block(pages_num_per_block, global_id++); // 申请新块
            b->used_pages++;
            allocable_blocks_rand.push_back(*b); 
            bmap.insert({b->id, b});
            
        } else {
            b = &(*(allocable_blocks_rand.begin()));
            b->used_pages++;
            if(b->used_pages == b->total_pages)
                allocable_blocks_rand.pop_front();
        }

        return b->id;
    }

    int allocate_page_high_utilization() {
        page_alloc++;

        Block* b = nullptr;
        if (allocable_blocks.size() == 0) {
            block_alloc++;
            b = new Block(pages_num_per_block, global_id++);
            b->used_pages++;
            allocable_blocks.insert(b);
            bmap.insert({b->id, b});
        } else {
            auto it = allocable_blocks.begin(); 
            b = *it;
            allocable_blocks.erase(b);
            b->used_pages++;
            if(b->used_pages != b->total_pages)
                allocable_blocks.insert(b);
        }
        return b->id;
    }

    void release_page(int id, bool high_utilization) {
        page_release++;
        auto it = bmap.find(id);
        if(it == bmap.end())
            return;
        auto b = it->second;

        if(high_utilization) {
            allocable_blocks.erase(b);
            if(b->used_pages <= 1) {
                block_release++;
                bmap.erase(it);
                delete b;
                return;
            } else {
                b->used_pages--;
            }
            allocable_blocks.insert(b);
        } else {
            if(b->used_pages <= 1) {
                auto it_rand = allocable_blocks_rand.iterator_to(*b);
                allocable_blocks_rand.erase(it_rand);
                block_release++;
                bmap.erase(it);
                delete b;
                return;
            } else {
                if(b->used_pages == b->total_pages)
                    allocable_blocks_rand.push_back(*b);
                b->used_pages--;
            }
        }
        
    }

};



void memutil_test(bool high_utilization, Allocator* allocator) {
    std::list<int> bid_list;
    static std::mt19937 gen(static_cast<unsigned>(std::time(nullptr)));
    std::bernoulli_distribution dist(0.9);

    for(int i = 0; i < (1250 * 1024); ++i) {
        allocator->allocator_mutex.lock();
        int bid;
        if(high_utilization) {
            bid = allocator->allocate_page_high_utilization();
        } else {
            bid = allocator->allocate_page_random();
        }
        bid_list.push_back(bid);
        allocator->allocator_mutex.unlock();
    }


    for(int i = 0; i < 20; ++i) {
        std::vector<std::list<int>::iterator> del_bid;
        for(auto it = bid_list.begin();it != bid_list.end(); ++it) {
            if (dist(gen)) {
                del_bid.push_back(it);
            }
        }
        int count = del_bid.size();
        for(auto it : del_bid) {
            allocator->allocator_mutex.lock();
            allocator->release_page(*it, high_utilization);
            allocator->allocator_mutex.unlock();
            bid_list.erase(it);
        }
        for(int i = 0;i < count; ++i) {
            allocator->allocator_mutex.lock();
            int bid;
            if(high_utilization) {
                bid = allocator->allocate_page_high_utilization();
            } else {
                bid = allocator->allocate_page_random();
            }
            bid_list.push_back(bid);
            allocator->allocator_mutex.unlock();
        }
        
    }

    return;
}



void print_info(Allocator* allocator) {
    //std::this_thread::sleep_for(std::chrono::seconds(5));
    int count = 20;
    std::vector<double> utils;
    while(!flag) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        double usage = (double)(allocator->page_alloc.load() - allocator->page_release.load());
        double total = (double)((allocator->block_alloc.load() - allocator->block_release.load()) * pages_num_per_block);
        std::cout << "useage :" << usage << ", total : " << total << ", utilization : " << usage/total << std::endl;
        utils.push_back(usage/total);
    }

    double sum = 0.0;
    for(auto u : utils) {
        sum += u;
    }
    std::cout << "Avg utilization: " << sum/utils.size() << std::endl;

    return;
}

int main(int argc, char *argv[]) {
    const bool use_high_mem = atoi(argv[1]);

    if(use_high_mem)
        std::cout<< "We simulate with our high_mem algorithm."<< std::endl;
    else
        std::cout<< "We simulate with naive random algorithm."<< std::endl;

    Allocator* a = new Allocator();
    std::thread* t[9];
    t[0] = new std::thread(&print_info, a);

    for(int i = 1;i <= 8; i++) {
        t[i] = new std::thread(&memutil_test, use_high_mem, a);
    }
    
    for(int i = 1;i <= 8; ++i) {
        t[i]->join();
    }

    flag = true;
    t[0]->join();
    
    return 0;
}
