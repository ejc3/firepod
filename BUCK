# Root Buck2 build file

load("@prelude//platforms:defs.bzl", "execution_platform")

# Define execution platform
execution_platform(
    name = "platforms",
    cpu_configuration = select({
        "DEFAULT": "x86_64",
    }),
    os_configuration = select({
        "DEFAULT": "linux",
    }),
)
