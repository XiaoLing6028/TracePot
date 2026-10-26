#pragma once

// Strace output samples used by tst_strace_parser. They live in a separate translation unit
// because moc's tokenizer cannot parse raw string literals full of unbalanced quotes.

namespace samples {

extern const char* const kOpenatLine;
extern const char* const kConnectRefused;
extern const char* const kOpenDeletedFile;
extern const char* const kHostileFileName;
extern const char* const kFakeReturnInName;
extern const char* const kControlCharacterName;
extern const char* const kOctalUtf8;
extern const char* const kOctalDnsPayload;
extern const char* const kHexEscapes;
extern const char* const kSimpleEscapes;
extern const char* const kTruncatedString;
extern const char* const kArgvArray;
extern const char* const kInet6Address;
extern const char* const kUnixAddress;
extern const char* const kAbstractUnixAddress;
extern const char* const kStructuredArguments;
extern const char* const kUnfinishedExecve;

}  // namespace samples
