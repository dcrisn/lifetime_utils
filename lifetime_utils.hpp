// Safe logical lifetime management for asynchronous and deferred systems.
// Provides guard/bind tools, soft/hard invalidation, and thread-safety policy
// control.

#pragma once

/* C++ stdlib */
#include <memory>
#include <mutex>
#include <stdexcept>
#include <type_traits>

namespace tarp {

// Thrown when an expired lifetime was provided when a valid one was expected.
struct bad_lifetime : std::exception {
    bad_lifetime() = delete;

    bad_lifetime(std::string const &s) : m_what(s) {}

    const char *what() const noexcept override { return m_what.c_str(); }

private:
    std::string m_what {};
};

//

namespace detail {
namespace type_traits {
// ---------------------------------------------------------------
// Policy types meant for compile-time elision of std::mutex
// and lock overhead where no thread-safety is needed.
// For example, in the context of a single-threaded environment
// or simply when not exposed to multithreaded access.
struct thread_safe : public std::true_type {};

struct thread_unsafe : public std::false_type {};

// Define two member types: mutex_t and lock_t. When the policy is
// thread_safe, mutex_t is a std::mutex and lock_t a std::lock_guard.
// When the policy is thread_unsafe, the mutex_t and lock_t types
// are defined to be empty dummy types.
//
// A class that wants to support conditionally compiling in/out
// thread-safety i.e. calls to lock mutexes, needs to:
// 1) take a policy template parameter, to be forwarded to ts_types.
// 2) use the lock_t and mutex_t types defined by ts_types.
template<typename policy,
         typename mutex_type = std::mutex,
         template<typename> typename lock_type = std::lock_guard>
struct ts_types {
    static_assert(std::is_same_v<policy, thread_safe> ||
                  std::is_same_v<policy, thread_unsafe>);

    struct dummy_mutex {};

    struct dummy_lock {
        dummy_lock(dummy_mutex &) {}
    };

    using mutex_t = std::conditional_t<std::is_same_v<policy, thread_safe>,
                                       mutex_type,
                                       dummy_mutex>;

    using lock_t = std::conditional_t<std::is_same_v<policy, thread_safe>,
                                      lock_type<mutex_type>,
                                      dummy_lock>;
};
}  // namespace type_traits
}  // namespace detail

//

// When using the 'lifetime anchor' approach it is necessary to perfom a
// two-stage construction. Given a class X inheriting from lifetime_anchor
// and hence from std::enable_shared_from_this, if X has a member Y
// that must be handed a weak_lifetime, then Y cannot be constructed
// in the X constructor, since std::shared_from_this() or std::weak_from_this()
// will **not** yield a valid pointer, as X has not yet finished constructing.
// Hence Y's construction must be _delayed_. We can achieve this either
// by storing it in a std::optional or std::unique_ptr. Note in both cases
// Y remains coupled in lifetime to X (which, by contrast, would not
// be true if Y was a std::shared_ptr). This is desirable.
// This class makes such delayed/two-stage construction clear and simplifies
// this approach. Y gets wrapped in delayed_construction<> and can be
// constructed subsequently by invoking the .construct() method.
//
// NOTE: if the member object is a unique_ptr, std::optional,
// or shared_ptr already, then this is of course not needed.
// Only _needed_ for objects that are constructed in place and have
// no default constructor.
template<typename T>
class delayed_construction {
public:
    bool constructed() const { return m_obj != nullptr; }

    template<typename... vargs>
    void construct(vargs &&...args) {
        m_obj = std::make_unique<T>(std::forward<vargs>(args)...);
    }

    T &operator*() {
        check_constructed();
        return *m_obj;
    }

    T &operator*() const {
        check_constructed();
        return *m_obj;
    }

    T *operator->() {
        check_constructed();
        return m_obj.get();
    }

    T *operator->() const {
        check_constructed();
        return m_obj.get();
    }

    T &get() {
        check_constructed();
        return *m_obj;
    }

    T &get() const {
        check_constructed();
        return *m_obj;
    }

private:
    void check_constructed() {
        if (!m_obj) {
            throw std::runtime_error(
              "illegal attempt to dereference object not yet constructed");
        }
    }

private:
    // NOTE: on the current system, std::optional<T> is twice the size of T.
    // std::unique_ptr is 8 bytes, + (when allocated) the size of T.
    // For small objects <= 4 bytes, the std::optional would be lighter;
    // however, the std::unique_ptr overhead is fixed no matter the
    // size of T, hence a unique_ptr is used here as that is preferable
    // in the general, assuming dynamic memory allocation is not a constraint.
    std::unique_ptr<T> m_obj;
};

namespace detail {
// Invoke callback if guard=true. Else if guard_false, return
// a value-initialized instance of type T, where T is the
// type of the return value of callback, and must
// have a default constructor (or be void).
template<typename callback_t, typename... vargs>
auto maybe_invoke(bool guard, callback_t &&cb, vargs &&...args) {
    using return_t = std::invoke_result_t<callback_t, vargs...>;
    if (guard) {
        return cb(std::forward<decltype(args)>(args)...);
    }
    if constexpr (std::is_void_v<return_t>) {
        return;
    } else {
        return return_t {};
    }
}
}  // namespace detail

//

// Base class for managing logical object lifetimes in asynchronous contexts.
//
// Inherits from std::enable_shared_from_this to enable safe shared ownership.
// Designed to be subclassed by objects passed into long-lived contexts
// (e.g., lambdas, ASIO handlers) where use-after-free is otherwise a risk.
//
// External components store a weak_ptr or a shared_ptr to this object,
// depending on the case; they must check its validity before invoking
// any logic that is dependent on this object being alive. Alive - AND
// valid: even if the shared_ptr is still physically alive, the logical
// lifetime may have been explicitly invalidated.
//
// Provides two modes of logical invalidation:
//  - Soft: via version bumping, invalidating callbacks tied to earlier
//  versions.
//  - Hard: via permanent invalidation, marking the object as logically
//  expired.
//
// Finally, physical invalidation (shared_ptr/weak_ptr are null) naturally
// means the object is no longer alive or valid.
//
// Always use guard/bind helpers to ensure safe lifetime usage in async code.
class lifetime_anchor_base
    : public std::enable_shared_from_this<lifetime_anchor_base> {
public:
    using weak_lifetime_t = std::weak_ptr<lifetime_anchor_base>;
    using strong_lifetime_t = std::shared_ptr<lifetime_anchor_base>;
    using version_counter_t = std::uint32_t;

private:
    // magic constant representing permanent logical invalidation
    static inline constexpr version_counter_t m_INVALID_LIFETIME_VERSION =
      std::numeric_limits<version_counter_t>::max();

    version_counter_t m_version = 0;

protected:
    // -------------------
    // Thread-unsafe methods to be invoked by derived classes, possibly
    // after wrapping them for thread safety.
    // -------------------

    // True if lifetime has not been permanently logically invalidated.
    bool check_valid() const { return m_version != m_INVALID_LIFETIME_VERSION; }

    // True if lifetime 1) has not been permanently logically invalidated
    // AND 2) version is the same as the current version.
    bool check_valid(version_counter_t version) const {
        if (m_version == m_INVALID_LIFETIME_VERSION) {
            return false;
        }

        return version == m_version;
    }

    // Increment the current version. This may wrap around.
    // If the current version is set to the permanently-invalidated
    // magic value, then nothing is done.
    // Incrementing the version naturally invalidates all contexts
    // tied to the old version (e.g. guarded lambdas).
    void do_bump_version() {
        // No version bump possible if permanently invalidated.
        if (m_version == m_INVALID_LIFETIME_VERSION) {
            return;
        }

        if (++m_version == m_INVALID_LIFETIME_VERSION) {
            ++m_version;
        }
    }

    // Permanently logically invalidate the lifetime.
    // After this, the current version cannot be bumped any more.
    // The lifetime, even if physically alive, is logically
    // invalid.
    void do_invalidate_lifetime() { m_version = m_INVALID_LIFETIME_VERSION; }

    // Return the current version.
    version_counter_t do_get_current_version() const { return m_version; }

public:
    lifetime_anchor_base() = default;

    // return the result of weak_from_this(), i.e. a weak_lifetime_t.
    weak_lifetime_t weak_lifetime() { return weak_from_this(); }

    // use a weak lifetime guard if use_lifetime=true. Else if
    // use_lifetime=false, then the guard does nothing and the callback
    // will be unconditionally invoked.
    // This is useful to minimize if-else conditional clutter
    // when the lifetime is only conditionally used.
    template<typename callback>
    [[nodiscard]] static auto maybe_guard_lifetime(bool use_lifetime,
                                                   weak_lifetime_t lifetime,
                                                   callback cb) {
        version_counter_t version = 0;

        if (use_lifetime) {
            const auto tmp = lifetime.lock();
            if (!tmp) {
                throw bad_lifetime("guard_lifetime() given expired lifetime "
                                   "with use_lifetime=true");
            }
            version = tmp->current_version();
        }

        return [use_lifetime,
                version,
                weak_lifetime = std::move(lifetime),
                h = std::move(cb)](auto &&...args) {
            static_assert(std::is_invocable_v<callback, decltype(args)...>,
                          "bad callback in maybe_guard_lifetime()");

            const auto invoke = [&](bool ok) {
                return detail::maybe_invoke(
                  ok, h, std::forward<decltype(args)>(args)...);
            };

            if (use_lifetime) {
                const auto ptr = weak_lifetime.lock();
                const bool ok = ptr && ptr->is_valid(version);
                return invoke(ok);
            }

            // anchor either unused or used AND !nullptr; version unimportant.
            return invoke(true);
        };
    }

    // If use_lifetime=true, then capture a strong_lifetime to ensure
    // the lifetime is physically alive at the time of invoking
    // the callback. Logical validity checks are also performed,
    // as for maybe_guard_lifetime. Else if use_lifetime=false,
    // then no lifetime capture occurs and the callback will be
    // unconditionally invoked.
    // This is useful to minimize if-else conditional clutter
    // when the lifetime is only conditionally used.
    template<typename callback>
    [[nodiscard]] static auto maybe_bind_lifetime(bool use_lifetime,
                                                  weak_lifetime_t lifetime,
                                                  callback cb) {
        strong_lifetime_t strong_lifetime;
        version_counter_t version = 0;
        if (use_lifetime) {
            strong_lifetime = lifetime.lock();
            if (strong_lifetime == nullptr) {
                throw std::runtime_error(
                  "bind_lifetime() failed to lock weak lifetime");
            }
            version = strong_lifetime->current_version();
        }

        return [strong_lifetime = std::move(strong_lifetime),
                version,
                h = std::move(cb)](auto &&...args) {
            static_assert(std::is_invocable_v<callback, decltype(args)...>,
                          "bad callback in maybe_bind_lifetime()");
            const auto invoke = [&](bool ok) {
                return detail::maybe_invoke(
                  ok, h, std::forward<decltype(args)>(args)...);
            };

            // implies use_lifetime=true.
            if (strong_lifetime) {
                const bool ok = strong_lifetime->is_valid(version);
                return invoke(ok);
            }

            // lifetime unused; call unconditionally; version unimportant.
            return invoke(true);
        };
    }

public:
    virtual ~lifetime_anchor_base() = default;

    // must be implemented by subclasses that must be
    // lifetime_anchors. Used because delayed construction
    // (i.e. 2-step construction) is necessary, since
    // a valid shared_from_this can only be obtained
    // once the constructor of this class has run.
    virtual void construct() = 0;

    // Permanently invalidate the lifetime.
    //
    // This sets the internal version counter to a reserved sentinel value.
    // Any callbacks checked after this call will be considered invalid,
    // regardless of the version they captured.
    //
    // This is the "final" state of the object’s logical lifetime,
    // even if the object continues to exist in memory.
    //
    // For soft, token-based invalidation, prefer bump_version().
    virtual void invalidate_lifetime() = 0;

    // Bump the internal version counter to a new value.
    //
    // Callbacks capture the version at the time of their creation.
    // Upon invocation, this version is compared against the current version.
    // If different, the callback is considered stale and not invoked.
    //
    // This provides a soft invalidation mechanism loosely similar to
    // version vectors in distributed systems.
    //
    // NOTE: In the thread-safe version, this check is race-free at the memory
    // level, but there is an inherent time-of-check-time-of-use (TOCTOU)
    // window:
    //
    //   Thread A: capture version -> ok
    //   Thread A: check version still valid -> ok
    //   Thread B: bump version
    //   Thread A: invokes callback (on now-stale version)
    //
    // This is accepted by design. If stricter guarantees are needed,
    // the callback itself must validate its context with more
    // stringent checks.
    virtual void bump_version() = 0;

    // Returns true if the lifetime has not been permanently invalidated.
    virtual bool is_valid() const = 0;

    // Returns true if the provided version is still valid AND the lifetime
    // has not been permanently invalidated.
    virtual bool is_valid(version_counter_t) const = 0;

    // Returns the current version counter. Captured by lambdas to perform
    // soft logical validation at invocation time.
    virtual version_counter_t current_version() const = 0;

    // This guards the invocation of cb on two levels. cb is invoked IFF:
    // - a weak_ptr to THIS can be locked (=> physical validity)
    // - the version has not been invalidated (=> logical validity)
    //
    // This is the default when a callback does not _need_ to keep
    // an object alive but must also not be invoked if the object is
    // no longer alive.
    template<typename callback>
    [[nodiscard]] auto guard_lifetime(callback cb) {
        return maybe_guard_lifetime(true, weak_from_this(), std::move(cb));
    }

    // This binds the lifetime of the current object to the lifetime of
    // the cb so that the current object lives _at least_ as long as cb
    // and may outlive it if other references keep it alive.
    // The lifetime will always be alive (physically valid) at the
    // time of invoking the lambda. In addition to this, the invocation
    // is guarded via logical validity checks, similar to guard_lifetime.
    //
    // NOTE: use with caution. While this ensures safety, it can cause
    // memory leaks if misused (e.g. if cb is stored somewhere and never
    // destructed!).
    template<typename callback>
    [[nodiscard]] auto bind_lifetime(callback cb) {
        return maybe_bind_lifetime(true, weak_from_this(), std::move(cb));
    }
};

// concrete lifetime-anchor base class, with optional thread safety.
template<typename thread_safety_policy = detail::type_traits::thread_safe>
class lifetime_anchor : public lifetime_anchor_base {
    static_assert(
      std::is_same_v<thread_safety_policy, detail::type_traits::thread_safe> ||
      std::is_same_v<thread_safety_policy, detail::type_traits::thread_unsafe>);

    using ts_policy = detail::type_traits::ts_types<thread_safety_policy>;

public:
    virtual ~lifetime_anchor() = default;

    bool is_valid() const override {
        typename ts_policy::lock_t l {m_mtx};
        return check_valid();
    }

    bool is_valid(version_counter_t version) const override {
        typename ts_policy::lock_t l {m_mtx};
        return check_valid(version);
    }

    void invalidate_lifetime() override {
        typename ts_policy::lock_t l {m_mtx};
        do_invalidate_lifetime();
    }

    void bump_version() override {
        typename ts_policy::lock_t l {m_mtx};
        do_bump_version();
    }

    version_counter_t current_version() const override {
        typename ts_policy::lock_t l {m_mtx};
        return do_get_current_version();
    }

private:
    mutable typename ts_policy::mutex_t m_mtx;
};

// thread safe concrete lifetime anchor base class.
using lifetime_anchor_ts = lifetime_anchor<detail::type_traits::thread_safe>;

// thread un-safe concrete lifetime anchor base class.
using lifetime_anchor_tu = lifetime_anchor<detail::type_traits::thread_unsafe>;

using weak_lifetime_t = lifetime_anchor_base::weak_lifetime_t;
using strong_lifetime_t = lifetime_anchor_base::strong_lifetime_t;

#if __cplusplus >= 202002L
template<typename T>
concept is_lifetime_anchor = std::derived_from<T, lifetime_anchor_base> ||
                             std::derived_from<T, lifetime_anchor_ts> ||
                             std::derived_from<T, lifetime_anchor_tu>;
#endif

template<typename callback>
auto maybe_guard_lifetime(bool use_lifetime,
                          weak_lifetime_t lifetime,
                          callback cb) {
    return lifetime_anchor_base::maybe_guard_lifetime(
      use_lifetime, lifetime, std::move(cb));
}

template<typename callback>
auto maybe_bind_lifetime(bool use_lifetime,
                         weak_lifetime_t lifetime,
                         callback cb) {
    return lifetime_anchor_base::maybe_bind_lifetime(
      use_lifetime, lifetime, std::move(cb));
}

template<typename callback>
auto guard_lifetime(weak_lifetime_t lifetime, callback cb) {
    return lifetime_anchor_base::maybe_guard_lifetime(
      true, lifetime, std::move(cb));
}

template<typename callback>
auto bind_lifetime(weak_lifetime_t lifetime, callback cb) {
    return lifetime_anchor_base::maybe_bind_lifetime(
      true, lifetime, std::move(cb));
}

//

// Alternative guard/bind interface for minimum noise.
inline auto make_lifetime_guard(bool use_lifetime, weak_lifetime_t lifetime) {
    return [use_lifetime, lifetime = std::move(lifetime)](auto cb) {
        return maybe_guard_lifetime(
          use_lifetime, std::move(lifetime), std::move(cb));
    };
}

inline auto make_lifetime_guard(weak_lifetime_t lifetime) {
    return [lifetime = std::move(lifetime)](auto cb) {
        return guard_lifetime(std::move(lifetime), std::move(cb));
    };
}

inline auto make_lifetime_binder(bool use_lifetime, weak_lifetime_t lifetime) {
    return [use_lifetime, lifetime = std::move(lifetime)](auto cb) {
        return maybe_bind_lifetime(
          use_lifetime, std::move(lifetime), std::move(cb));
    };
}

inline auto make_lifetime_binder(weak_lifetime_t lifetime) {
    return [lifetime = std::move(lifetime)](auto cb) {
        return bind_lifetime(std::move(lifetime), std::move(cb));
    };
}

//

inline void throw_on_bad_lifetime(weak_lifetime_t lifetime) {
    if (auto tmp = lifetime.lock(); !tmp || !tmp->is_valid()) {
        throw bad_lifetime("Invalid lifetime provided");
    }
}

inline void throw_on_bad_lifetime(strong_lifetime_t lifetime) {
    if (!lifetime || !lifetime->is_valid()) {
        throw bad_lifetime("Invalid lifetime provided");
    }
}

}  // namespace tarp
