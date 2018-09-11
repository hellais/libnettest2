# measurement-kit/libnettest2

C++11 header only implementation of the MK nettest workflow [documented
as JavaScript pseudo-code in MK sources](https://github.com/measurement-kit/measurement-kit/tree/master/include/measurement_kit#task-pseudocode).

For now, this is still quite experimental code. The plan is to start
integrating this with MK and learn about what is missing and what can
be improved easily.

The goal is to keep the whole implementation as a single header with
minimal dependencies and within around 5-10K lines of code.

Depends on:

- nlohmann/json
- HowardHinnant/date
- curl/curl
- maxmind/libmaxminddb

Compile on macOS as a standalone integration test using:

```
clang++ -Wall -Wextra -std=c++11 -lmaxminddb -lcurl integration-test.cpp
```

Assumes that you dropped `json.hpp` and `date.h` on the current directory.
