add_library(egress_sanitizer SHARED main.cpp)
configure_DynamoRIO_client(egress_sanitizer)
target_link_libraries(egress_sanitizer libdft-dr)
foreach (ext drmgr drreg drx drwrap drsyms drutil)
    use_DynamoRIO_extension(egress_sanitizer ${ext})
endforeach ()
set_target_properties(egress_sanitizer PROPERTIES
    OUTPUT_NAME "libdft-egress-dr" PREFIX "")
