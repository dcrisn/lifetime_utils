# lifetime_utils
Single-header set of utilities to make callback-based asynchronous code safe and prevent use-after-free memory violations.

## Brief

Lambdas in c++ are extremely convenient. They are also dangerous as they can be
be easily misused. By-reference captures can easily turn into use-after-free
memory violations by accessing memory of now-destructed objects.
Lambdas are particularly common in asynchronous code -- for example using
the `asio` library. Such callback-heavy code is therefore particularly
prone to the aforementioned perils and the lifetime of objects must be
carefully reasoned about and handled.

This project consists of a single-header set of utilities, `lifetime_utils.hpp`,
which provides some tools to help make such code safe. These include a
base class and various helper functions. They revolve around the idea
of a `lifetime_anchor` that can be invalidated in various ways and which
is used to guard the invocation of callbacks to prevent use-after-free.

### Example

A small example is given below.
This is taken from a longer discusion [here](https://dcrisn.github.io/asio-lifetimes/#asio-lifetime-dependencies-and-use-after-free-cases).
```c++
using namespace std::chrono_literals;

namespace asio = boost::asio;

class connection {
public:
    // a member object that schedules callbacks takes a weak lifetime
    // parameter (weak_ptr to the lifetime anchor).
    connection(asio::io_context &ioctx, weak_lifetime_t lifetime)
        : m_lifetime(std::move(lifetime)), m_timer(ioctx) {}

    void restart_heartbeat_monitor() {
        // Any pending async waits will be canceled.
        m_timer.expires_after(m_HEARTBEAT_INTERVAL);

        // turn the weak lifetime into a _strong_ lifetime,
        // ensuring the lifetime is physically alive when
        // the callback is to be invoked.
        const auto safe = make_lifetime_binder(m_lifetime);

        // call handler on timeout or cancellation: safe from
        // use-after free due to checks carried out by
        // safe().
        m_timer.async_wait(safe([this](std::error_code ec) {
            if (ec) {
                if (ec.value() != asio::error::operation_aborted) {
                    m_sig_error.emit(ec.message());
                }
                return;
            }

            on_heartbeat_timeout();
        }));

        // NOTE: the above can also be written as:
        // m_timer.async_wait(bind_lifetime(m_lifetime, <LAMBDA>));
    };
    ...
```

## Documentation

Documentation can be found inside the header itself and a longer discussion
of both the concept and the motivation for it can be found
[here](https://dcrisn.github.io/asio-lifetimes/#asio-lifetime-dependencies-and-use-after-free-cases).
