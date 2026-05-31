add_library(synthetic_unit SHARED main.cpp)
configure_DynamoRIO_client(synthetic_unit)
target_link_libraries(synthetic_unit libdft-dr)
foreach (ext drmgr drreg drx drwrap drsyms drutil)
    use_DynamoRIO_extension(synthetic_unit ${ext})
endforeach ()
set_target_properties(synthetic_unit PROPERTIES
    OUTPUT_NAME "libdft-synthetic-unit-dr" PREFIX "")
