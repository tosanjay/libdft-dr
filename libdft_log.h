/* Logging shim for the DR port.
 *
 * libdft64 routes verbose tracing through Pin's LOG() (writes pintool.log) and
 * builds the message with Pin string helpers (decstr/hexstr/StringFromAddrint).
 * Those helpers do not exist under DR. Since LOG is pure tracing with no side
 * effects, we expand it to nothing: the variadic macro consumes the argument
 * tokens unevaluated, so the Pin string helpers are never referenced and the
 * hot source-painting paths carry zero logging cost. Flip to a dr_fprintf form
 * here if a future debugging session needs the traces back.
 */
#ifndef __LIBDFT_LOG_H__
#define __LIBDFT_LOG_H__

#define LOG(...) ((void)0)

#endif /* __LIBDFT_LOG_H__ */
