add_library(file_introspect SHARED main.cpp)
configure_DynamoRIO_client(file_introspect)
target_link_libraries(file_introspect libdft-dr)
foreach (ext drmgr drreg drx drwrap drsyms drutil)
    use_DynamoRIO_extension(file_introspect ${ext})
endforeach ()
set_target_properties(file_introspect PROPERTIES
    OUTPUT_NAME "libdft-introspect-dr" PREFIX "")
