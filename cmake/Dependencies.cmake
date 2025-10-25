function(_lantern_define_interface target_name source_dir)
    if(NOT TARGET ${target_name})
        add_library(${target_name} INTERFACE)
    endif()

    if(EXISTS ${source_dir}/include)
        target_include_directories(${target_name} INTERFACE ${source_dir}/include)
    elseif(EXISTS ${source_dir})
        message(WARNING "${target_name} has no include directory at ${source_dir}/include")
    else()
        message(WARNING "Missing dependency sources at ${source_dir}. Run scripts/bootstrap.sh to fetch git submodules.")
    endif()
endfunction()

function(lantern_configure_dependencies target)
    if(NOT TARGET ${target})
        message(FATAL_ERROR "lantern_configure_dependencies expects an existing CMake target")
    endif()

    set(external_root ${PROJECT_SOURCE_DIR}/external)

    _lantern_define_interface(lantern_libp2p ${external_root}/c-libp2p)
    _lantern_define_interface(lantern_c_ssz ${external_root}/c-ssz)

    target_link_libraries(${target}
        PUBLIC
            lantern_libp2p
            lantern_c_ssz
    )
endfunction()
