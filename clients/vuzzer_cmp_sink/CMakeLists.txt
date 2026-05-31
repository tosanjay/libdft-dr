# vuzzer_cmp_sink -- vuzzer64-v2 reference client.
# Produces libdft64-style cmp.out + lea.out from CMP/LEA sinks.

add_library(vuzzer_cmp_sink SHARED main.cpp)
# Public headers come transitively via libdft-dr's PUBLIC include dir.
configure_DynamoRIO_client(vuzzer_cmp_sink)
target_link_libraries(vuzzer_cmp_sink libdft-dr)
foreach (ext drmgr drreg drx drwrap drsyms drutil)
    use_DynamoRIO_extension(vuzzer_cmp_sink ${ext})
endforeach ()
# Output as libdft-dta-dr-v2.so to coexist with the legacy single-shot tool
# during the M3.2 step-3 parity A/B.
set_target_properties(vuzzer_cmp_sink PROPERTIES
    OUTPUT_NAME "libdft-dta-dr-v2" PREFIX "")
