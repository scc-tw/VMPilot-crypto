include(FetchContent)

function(CPMAddPackage)
    set(options)
    set(oneValueArgs NAME GITHUB_REPOSITORY GIT_TAG VERSION SOURCE_DIR)
    set(multiValueArgs GIT_SUBMODULES DOWNLOAD_COMMAND PATCH_COMMAND)
    cmake_parse_arguments(CPM "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT CPM_NAME)
        message(FATAL_ERROR "CPMAddPackage requires NAME")
    endif()

    if(CPM_SOURCE_DIR)
        add_subdirectory(${CPM_SOURCE_DIR} ${CPM_NAME})
        return()
    endif()

    if(CPM_GITHUB_REPOSITORY)
        set(repo_url https://github.com/${CPM_GITHUB_REPOSITORY}.git)
    else()
        message(FATAL_ERROR "CPMAddPackage requires GITHUB_REPOSITORY when SOURCE_DIR is not given")
    endif()

    if(CPM_GIT_TAG)
        set(tag ${CPM_GIT_TAG})
    elseif(CPM_VERSION)
        set(tag ${CPM_VERSION})
    else()
        message(FATAL_ERROR "CPMAddPackage requires GIT_TAG or VERSION")
    endif()

    FetchContent_Declare(
        ${CPM_NAME}
        GIT_REPOSITORY ${repo_url}
        GIT_TAG ${tag}
        GIT_SHALLOW TRUE
        GIT_SUBMODULES ${CPM_GIT_SUBMODULES}
        DOWNLOAD_COMMAND "${CPM_DOWNLOAD_COMMAND}"
        PATCH_COMMAND "${CPM_PATCH_COMMAND}"
    )

    FetchContent_MakeAvailable(${CPM_NAME})
endfunction()
