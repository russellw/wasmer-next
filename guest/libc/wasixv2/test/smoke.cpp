// C++ smoke test for wasixv2/test/run.sh: links libc++ and libc++abi, and,
// in the eh configuration, throws through a function into a catch.
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#if __cpp_exceptions
[[gnu::noinline]] static int parse(const std::string &text) { return std::stoi(text); }
#endif

int main() {
	int value = 0;
#if __cpp_exceptions
	try {
		value = parse("not a number");
	} catch (const std::invalid_argument &) {
		value = 1;
	}
#else
	value = 1;
#endif
	std::mutex lock;
	std::vector<std::thread> threads;
	for (int i = 0; i < 2; i++)
		threads.emplace_back([&] {
			std::lock_guard<std::mutex> guard(lock);
			value++;
		});
	for (auto &thread : threads)
		thread.join();
	std::cout << "hello from wasixv2 C++: " << value << std::endl;
	return value == 3 ? 0 : 1;
}
