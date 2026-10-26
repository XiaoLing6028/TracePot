#pragma once

#include <optional>
#include <string>
#include <utility>
#include <variant>

namespace tracepot {

enum class ErrorCode {
    InvalidArgument,
    InputNotFound,
    InputRejected,
    UnsupportedInput,
    ArchiveUnsafe,
    ArchiveMalformed,
    ArchiveLimitExceeded,
    EntryPointNotFound,
    SandboxUnavailable,
    ObserverUnavailable,
    LaunchFailed,
    Io,
    Cancelled,
    ReportInvalid,
    Internal,
};

std::string_view enumName(ErrorCode code);

// A structured error: what went wrong plus, when possible, what the user can do about it.
struct Error {
    ErrorCode code = ErrorCode::Internal;
    std::string message;
    std::string hint;

    [[nodiscard]] std::string describe() const;
};

inline Error makeError(ErrorCode code, std::string message, std::string hint = {})
{
    return Error{code, std::move(message), std::move(hint)};
}

// Minimal value-or-error type (std::expected is C++23).
template <typename T>
class [[nodiscard]] Result {
public:
    Result(T value) : storage_(std::move(value)) {}  // NOLINT(google-explicit-constructor)
    Result(Error error) : storage_(std::move(error)) {}  // NOLINT(google-explicit-constructor)

    [[nodiscard]] bool ok() const { return std::holds_alternative<T>(storage_); }
    explicit operator bool() const { return ok(); }

    T& value() & { return std::get<T>(storage_); }
    const T& value() const& { return std::get<T>(storage_); }
    T&& value() && { return std::get<T>(std::move(storage_)); }

    T* operator->() { return &value(); }
    const T* operator->() const { return &value(); }
    T& operator*() & { return value(); }
    const T& operator*() const& { return value(); }

    [[nodiscard]] const Error& error() const { return std::get<Error>(storage_); }

private:
    std::variant<T, Error> storage_;
};

template <>
class [[nodiscard]] Result<void> {
public:
    Result() = default;
    Result(Error error) : error_(std::move(error)) {}  // NOLINT(google-explicit-constructor)

    [[nodiscard]] bool ok() const { return !error_.has_value(); }
    explicit operator bool() const { return ok(); }
    [[nodiscard]] const Error& error() const { return *error_; }

private:
    std::optional<Error> error_;
};

using Status = Result<void>;

}  // namespace tracepot
