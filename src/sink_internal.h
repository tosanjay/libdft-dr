/* sink_internal.h -- INTERNAL dispatch interface for the sink registry.
 * NOT part of the public API. Consumed by libdft_core_dr.cpp (CMP/LEA emit
 * callsites) and implemented in api_sinks.cpp.
 */
#ifndef LIBDFT_DR_SINK_INTERNAL_H_
#define LIBDFT_DR_SINK_INTERNAL_H_

#include <string>
#include <vector>

#include "dr_api.h"

#include "libdft_dr/sinks.h"
#include "libdft_dr/tag.h"

namespace libdft_dr_internal {

/* Payload built by libdft_core_dr.cpp at each CMP/LEA emit point and handed
 * to the dispatcher. The public sink_context_t::_internal field points at one
 * of these. */
struct sink_payload {
    std::vector<std::string>   legacy_fields;  /* 21 for CMP, 10 for LEA */
    std::vector<libdft_dr::tag_t> operand_tags;  /* raw per-byte operand tags */
};

/* True iff at least one client has registered a sink for `cls`. The
 * libdft_core_dr.cpp callsites check this to skip payload construction +
 * dispatch when no sink is bound. */
bool has_sink(libdft_dr::opcode_class cls);

/* Invoke all registered sinks for `cls`. */
void dispatch_sink(libdft_dr::opcode_class cls,
                   void *drcontext, instr_t *instr, app_pc pc,
                   sink_payload &pl);

}  // namespace libdft_dr_internal

#endif  /* LIBDFT_DR_SINK_INTERNAL_H_ */
