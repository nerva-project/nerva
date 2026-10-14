/* A stand-in for Boost.Preprocessor's stringize.hpp, used only by the powbench
 * harnesses and only when real Boost headers are not installed.
 *
 * Why this exists: the benchmark build set pulls in hash-ops.h, which includes
 * epee's warnings.h, whose single use of Boost is
 *
 *   _Pragma(BOOST_PP_STRINGIZE(GCC diagnostic ignored BOOST_PP_STRINGIZE(-W##w)))
 *
 * That is the whole dependency. Requiring a Boost install to measure a hash
 * function has now cost time on three separate machines, most recently a Mac
 * where Homebrew refused to upgrade Boost because the Command Line Tools were
 * out of date. One macro is not worth that.
 *
 * The two-level expansion is the point and is what Boost does: the outer macro
 * has to expand its argument before the inner one stringizes it, or
 * BOOST_PP_STRINGIZE(SOME_MACRO) yields "SOME_MACRO" rather than its value.
 *
 * This is deliberately NOT on the include path of the daemon build. It is
 * passed only by the powbench build scripts, and only when the real header was
 * not found, so it can never shadow a real Boost installation. If you find
 * yourself adding it anywhere else, install Boost instead. */

#ifndef BOOST_PREPROCESSOR_STRINGIZE_HPP
#define BOOST_PREPROCESSOR_STRINGIZE_HPP

#define BOOST_PP_STRINGIZE(text) BOOST_PP_STRINGIZE_I(text)
#define BOOST_PP_STRINGIZE_I(...) #__VA_ARGS__

#endif
