# lifetime_utils

![Header-only](https://img.shields.io/badge/single--header-blue)
![C++17 / C++20](https://img.shields.io/badge/C%2B%2B-17%20%7C%2020-brightgreen)
![Thread-safe](https://img.shields.io/badge/thread--safety-optional-yellowgreen)
![Zero dependencies](https://img.shields.io/badge/dependencies-none-lightgrey)
![MIT License](https://img.shields.io/badge/license-MIT-blue)

Single-header set of utilities to make callback-based asynchronous code safe and prevent use-after-free memory violations.

## Brief

Lambdas in c++ are extremely convenient -- and also dangerous. By-reference
captures can easily lead to **use-after-free** memory violations
when asynchronous callbacks **outlive** the objects they access.
This is especially common in systems built with libraries like asio, where
callback-heavy code is the norm.

In such code, object lifetimes must be carefully managed across scheduling and
execution boundaries.

`lifetime_utils.hpp` provides a compact, composable set of tools to make this
safe and expressive. It introduces a `lifetime_anchor` abstraction — a logical
lifetime token that can be guarded or bound to a callback, allowing precise
control over when and whether a callback is allowed to run.

Callbacks will only execute if:

- The object is still physically alive (`shared_ptr` not expired)
- And logically valid (based on a monotonic version or final invalidation)

## Features

`lifetime_anchor_base`
the core base class with versioned logical lifetime tracking

`lifetime_anchor_ts` / `lifetime_anchor_tu`
thread-safe or thread-unsafe concrete versions

`guard_lifetime`, `bind_lifetime`, and `make_lifetime_{guard,binder}`
tools to wrap callbacks safely

Soft invalidation via version bumping, and final invalidation via
a sentinel version.

Optional two-phase construction support for post-constructor
member initialization.

## Example: asio timer

Taken from the longer writeup [here](https://dcrisn.github.io/asio-lifetimes/).

```C++
using namespace std::chrono_literals;
namespace asio = boost::asio;

class connection {
public:
    connection(asio::io_context &ioctx, weak_lifetime_t lifetime)
        : m_lifetime(std::move(lifetime)), m_timer(ioctx) {}

    void restart_heartbeat_monitor() {
        m_timer.expires_after(m_HEARTBEAT_INTERVAL);

        const auto safe = make_lifetime_binder(m_lifetime);

        m_timer.async_wait(safe([this](std::error_code ec) {
            if (ec && ec != asio::error::operation_aborted) {
                m_sig_error.emit(ec.message());
                return;
            }
            on_heartbeat_timeout();
        }));

        // Or, more directly:
        // m_timer.async_wait(bind_lifetime(m_lifetime, <lambda>));
    }

private:
    weak_lifetime_t m_lifetime;
    asio::steady_timer m_timer;
    ...
};
```
This ensures the callback won’t run unless the connection object is still
alive and logically valid at the time of execution.

## Documentation

Full documentation is provided inline in `lifetime_utils.hpp`.

A detailed blog post covering motivation, use cases, design decisions
and asynchronous programming with `asio` can be found
[here](https://dcrisn.github.io/asio-lifetimes/).


## Integration

Just drop `lifetime_utils.hpp` into your project. No dependencies.
Assumes `>= c++17`.



